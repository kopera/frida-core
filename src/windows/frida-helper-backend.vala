namespace Frida {
	private class WindowsRemoteAgent : Object {
		public State state {
			get;
			private set;
			default = State.STARTED;
		}

		public enum State {
			STARTED,
			STOPPED,
			PAUSED
		}

		private MainContext main_context;
		private Windows.ProcessHandle target;
		private string library_path;
		private string entrypoint;
		private string data;

		TimeoutSource? paused_timeout;

		private WindowsRemoteAgent (MainContext main_context, Windows.ProcessHandle target, string library_path,
				string entrypoint, string data) {
			this.main_context = main_context;
			this.target = target;
			this.library_path = library_path;
			this.entrypoint = entrypoint;
			this.data = data;
		}

		~WindowsRemoteAgent () {
			this.target.close ();
		}

		internal static async WindowsRemoteAgent start (MainContext main_context, Windows.ProcessHandle target, string library_path,
				string entrypoint, string data, Cancellable? cancellable) throws Error {
			var agent = new WindowsRemoteAgent (main_context, target, library_path, entrypoint, data);
			yield agent.inject (cancellable);

			return agent;
		}

		private async void inject (Cancellable? cancellable) throws Error {
			Windows.ThreadHandle agent_thread;
			void * agent_instance;
			_start (target, library_path, entrypoint, data, out agent_instance, out agent_thread);
			state = State.STARTED;

			var idle_source = new IdleSource ();
			idle_source.set_callback (() => {
				var wait_source = WaitHandleSource.create (agent_thread, true);
				wait_source.set_callback (() => {
					_free (agent_instance);

					if (state != State.PAUSED) {
						state = State.STOPPED;
					}

					return Source.REMOVE;
				});
				wait_source.attach (main_context);

				return Source.REMOVE;
			});
			idle_source.attach (main_context);
		}

		internal async void demonitor (Cancellable? cancellable)
			requires (state == State.STARTED)
		{
			state = State.PAUSED;

			paused_timeout = new TimeoutSource.seconds (20);
			paused_timeout.set_callback (() => {
				if (state == State.PAUSED) {
					state = State.STOPPED;
				}
				return Source.REMOVE;
			});
			paused_timeout.attach (main_context);
		}

		internal async void resume (Cancellable? cancellable)
			throws Error
			requires (state == State.PAUSED)
		{
			paused_timeout.destroy ();

			try {
				yield inject (cancellable);
			} catch (Error e) {
				printerr ("---> %s\n", e.message);
				state = State.STOPPED;
				throw e;
			}
		}

		private extern static void _start (Windows.ProcessHandle handle, string path, string entrypoint, string data,
			out void * agent_instance, out Windows.ThreadHandle agent_thread) throws Error;
		private extern static void _free (void * agent_instance);
	}


	public class WindowsHelperBackend : Object, WindowsHelper {
		public PrivilegeLevel level {
			get;
			construct;
		}

		public bool is_idle {
			get {
				return agents.is_empty;
			}
		}

		private Gee.Map<uint, WindowsRemoteAgent> agents = new Gee.HashMap<uint, WindowsRemoteAgent> ();

		private MainContext main_context;

		private AssetDirectory? asset_dir = null;
		private Gee.HashMap<string, AssetBundle> asset_bundles = new Gee.HashMap<string, AssetBundle> ();

		public WindowsHelperBackend (PrivilegeLevel level) {
			Object (level: level);
		}

		construct {
			main_context = MainContext.ref_thread_default ();
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (!is_idle) {
				var idle_handler = this.notify["is-idle"].connect (() => {
					if (is_idle) {
						close.callback ();
					}
				});
				yield;
				disconnect (idle_handler);
			}

			asset_bundles.clear ();
			asset_dir = null;
		}

		public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
				string[] dependencies, uint id, Cancellable? cancellable) throws Error {
			string library_path = yield library_file_path (pid, path_template, dependencies, cancellable);
			var process = open_process (pid);
			try {
				yield prepare_target (pid, process, cancellable);
				yield inject_target (id, process, library_path, entrypoint, data, cancellable);
			} catch (Error e) {
				process.close ();
				throw e;
			}
		}

		private async string library_file_path (uint pid, PathTemplate path_template, string[] dependencies, Cancellable? cancellable) throws Error {
			string path = path_template.expand (WindowsProcess.is_x64 (pid) ? "64" : "32");

			if (level == ELEVATED) {
				if (asset_dir == null)
					asset_dir = new AssetDirectory (cancellable);
				AssetBundle bundle = asset_bundles[path];
				if (bundle == null) {
					bundle = new AssetBundle.with_copy_of (path, dependencies, asset_dir, cancellable);
					asset_bundles[path] = bundle;
				}
				return bundle.files.first ().get_path ();
			} else {
				return path;
			}
		}

		private async void prepare_target (uint pid, Windows.ProcessHandle process, Cancellable? cancellable) {
			SourceFunc callback = prepare_target.callback;
			new Thread<void>("frida-helper-backend-prepare-target", () => {
				var has_msys = false;

				if (Windows.Debug.start (pid)) {
					while (true) {
						Windows.Debug.Event event;
						if (!Windows.Debug.wait (out event, 0)) {
							var is_timeout = Windows.Error.get_last () != Windows.Error.SEM_TIMEOUT;
							var is_cancelled = cancellable != null && cancellable.is_cancelled ();
							if (is_timeout|| is_cancelled)
								break;

							continue;
						}

						if (event.code == Windows.Debug.EventCode.LOAD_DLL) {
							var image_full_path = event.load_dll.get_image_name (process);
							if (image_full_path != null) {
								var image_basename = Path.get_basename (image_full_path);
								if (image_basename.ascii_casecmp("msys-2.0.dll") == 0) {
									has_msys = true;
								}
							}

							event.load_dll.handle.close ();
						}
		
						if (event.code == Windows.Debug.EventCode.EXCEPTION) {
							if (has_msys && event.exception.record.code != 0x406D1388)
								printerr("process waiting for msys initialization pid=%u\n", pid);

							// When the debugger starts a new target application, an initial breakpoint automatically
							// occurs after the main image and all statically-linked DLLs are loaded before any DLL
							// initialization routines are called.
							//
							// At this point, we can consider the application to be safely initialized, unless it is
							// msys/cygwin based.
							//
							// If the target process uses msys, we wait for it to be fully initialized. Ideally, we
							// would wait for the `cygwin_finished_initializing` variable to be set, however, if we look
							// at the source code, we notice that it makes a call to `SetThreadName` right before
							// setting the variable:
							// https://github.com/cygwin/cygwin/blob/579064bf4d408e99ed7556f36a3050c7ee99dee6/winsup/cygwin/dcrt0.cc#L944
							//
							// `SetThreadName` is implemented using a `RaiseException` as specified in:
							// https://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx)
							//
							// This allows us to simply wait for the right exception. ALternatively, we would need to
							// rely on debug symbols to find the memory location of `cygwin_finished_initializing` and
							// set a hardware breakpoint there.
							if (!has_msys
									|| (has_msys && event.exception.record.code == 0x406D1388)
									|| (Windows.Debug.ExceptionEvent.Flags.NONCONTINUABLE in event.exception.record.flags)) {
								if (has_msys && event.exception.record.code == 0x406D1388)
									printerr("process completed msys initialization pid=%u\n", pid);
								Windows.Debug.@continue(event.process_id, event.thread_id,
									Windows.Debug.ContinueStatus.EXCEPTION_NOT_HANDLED);
								break;
							}
						}

						Windows.Debug.@continue(event.process_id, event.thread_id,
							Windows.Debug.ContinueStatus.CONTINUE);
					}
		
					Windows.Debug.set_process_kill_on_exit (false);
					Windows.Debug.stop (pid);
				}

				Idle.add((owned) callback);
			});

			yield;
		}

		private async void inject_target (uint id, Windows.ProcessHandle target, string library_path, string entrypoint, string data, Cancellable? cancellable) throws Error {
			var agent = yield WindowsRemoteAgent.start (main_context, target, library_path, entrypoint, data, cancellable);
			agent.notify["state"].connect (() => {
				printerr ("Agent id: %u state: %s\n", id, agent.state.to_string ());
				if (agent.state == WindowsRemoteAgent.State.STOPPED) {
					uninjected (id);
					agents.unset (id);
				}
			});
			agents[id] = agent;
		}

		public async void demonitor (uint id, Cancellable? cancellable) throws Error, IOError {
			WindowsRemoteAgent? agent = agents[id];
			if (agent == null || agent.state != WindowsRemoteAgent.State.STARTED)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			yield agent.demonitor (cancellable);
		}

		public async void demonitor_and_clone_injectee_state (uint id, uint clone_id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported on windows");
		}

		public async void recreate_injectee_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			WindowsRemoteAgent? agent = agents[id];
			if (agent == null || agent.state != WindowsRemoteAgent.State.PAUSED)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			yield agent.resume (cancellable);
		}

		private extern static Windows.ProcessHandle open_process (uint pid) throws Error;
	}

	private class AssetDirectory {
		public File file {
			get;
			private set;
		}

		public AssetDirectory (Cancellable? cancellable) throws Error {
			try {
				string? program_files_path = Environment.get_variable ("ProgramFiles");
				assert (program_files_path != null);
				file = File.new_for_path (Path.build_filename (program_files_path, "Frida"));
				file.make_directory (cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.EXISTS)
					return;
				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}
		}

		~AssetDirectory () {
			try {
				var enumerator = file.enumerate_children ("standard::*", 0);

				FileInfo file_info;
				while ((file_info = enumerator.next_file ()) != null) {
					if (file_info.get_file_type () == DIRECTORY) {
						File subdir = file.get_child (file_info.get_name ());
						try {
							subdir.delete ();
						} catch (GLib.Error e) {
						}
					}
				}
			} catch (GLib.Error e) {
			}

			try {
				file.delete ();
			} catch (GLib.Error e) {
			}
		}
	}

	private class AssetBundle {
		public Gee.List<File> files {
			get;
			private set;
		}

		public AssetBundle.with_copy_of (string path, string[] dependencies, AssetDirectory directory,
				Cancellable? cancellable) throws Error {
			try {
				File target_dir;
				{
					uint8[] data;
					FileUtils.get_data (path, out data);
					string checksum = Checksum.compute_for_data (SHA1, data);
					target_dir = directory.file.get_child (checksum);
				}

				try {
					target_dir.make_directory ();
				} catch (GLib.Error e) {
					if (!(e is IOError.EXISTS))
						throw e;
				}

				File source_file = File.new_for_path (path);
				File source_dir = source_file.get_parent ();
				string name = source_file.get_basename ();

				var target_files = new Gee.ArrayList<File> ();

				File target_file = target_dir.get_child (name);
				target_files.add (target_file);
				if (!target_file.query_exists (cancellable)) {
					source_file.copy (target_file, FileCopyFlags.NONE, cancellable);
				}

				foreach (var dep_path in dependencies) {
					File source_dep = File.new_for_path (dep_path);
					if (source_dep.has_parent (source_dir)) {
						File target_dep = target_dir.get_child (source_dep.get_basename ());
						target_files.add (target_dep);
						if (!target_dep.query_exists (cancellable))
							source_dep.copy (target_dep, FileCopyFlags.NONE, cancellable);
					}
				}

				this.files = target_files;
			} catch (GLib.Error e) {
				throw new Error.INVALID_ARGUMENT ("%s", e.message);
			}
		}

		~AssetBundle () {
			foreach (var file in files) {
				try {
					file.delete ();
				} catch (GLib.Error e) {
				}
			}
		}
	}

	namespace WindowsSystem {
		public extern static bool is_x64 ();
	}

	namespace WindowsProcess {
		public extern static bool is_x64 (uint32 pid) throws Error;
	}

	namespace WaitHandleSource {
		internal extern Source create (Windows.Handle handle, bool owns_handle);
	}
}
