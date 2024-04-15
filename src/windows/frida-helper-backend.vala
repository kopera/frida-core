namespace Frida {
	public class WindowsHelperBackend : Object, WindowsHelper {
		public PrivilegeLevel level {
			get;
			construct;
		}

		private MainContext main_context;

		private Promise<bool> close_request;
		private uint pending = 0;

		private AssetDirectory? asset_dir = null;
		private Gee.HashMap<string, AssetBundle> asset_bundles = new Gee.HashMap<string, AssetBundle> ();

		public WindowsHelperBackend (PrivilegeLevel level) {
			Object (level: level);
		}

		construct {
			main_context = MainContext.ref_thread_default ();
		}

		public async void close (Cancellable? cancellable) throws IOError {
			while (close_request != null) {
				try {
					yield close_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			close_request = new Promise<bool> ();

			if (pending > 0) {
				try {
					yield close_request.future.wait_async (cancellable);
				} catch (Error e) {
					assert_not_reached ();
				}
			} else {
				close_request.resolve (true);
			}

			asset_bundles.clear ();
			asset_dir = null;
		}

		public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
				string[] dependencies, uint id, Cancellable? cancellable) throws Error {
			string path = path_template.expand (WindowsProcess.is_x64 (pid) ? "64" : "32");

			string target_dependent_path;
			if (level == ELEVATED) {
				if (asset_dir == null)
					asset_dir = new AssetDirectory (cancellable);
				AssetBundle bundle = asset_bundles[path];
				if (bundle == null) {
					bundle = new AssetBundle.with_copy_of (path, dependencies, asset_dir, cancellable);
					asset_bundles[path] = bundle;
				}
				target_dependent_path = bundle.files.first ().get_path ();
			} else {
				target_dependent_path = path;
			}

			var process = open_process (pid);
			try {
				yield prepare_target (pid, process, cancellable);

				void * instance, waitable_thread_handle;
				_inject_library_file (process, target_dependent_path, entrypoint, data, out instance, out waitable_thread_handle);
				if (waitable_thread_handle != null) {
					pending++;

					var source = new IdleSource ();
					source.set_callback (() => {
						monitor_remote_thread (id, instance, waitable_thread_handle);
						return false;
					});
					source.attach (main_context);
				}
			} finally {
				process.close ();
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
									|| event.exception.record.code == 0x406D1388
									|| (Windows.Debug.ExceptionEvent.Flags.NONCONTINUABLE in event.exception.record.flags)) {
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

		private void monitor_remote_thread (uint id, void * instance, void * waitable_thread_handle) {
			var source = WaitHandleSource.create (waitable_thread_handle, true);
			source.set_callback (() => {
				bool is_resident;
				_free_inject_instance (instance, out is_resident);

				uninjected (id);

				pending--;
				if (close_request != null && pending == 0)
					close_request.resolve (true);

				return false;
			});
			source.attach (main_context);
		}

		private extern static Windows.ProcessHandle open_process (uint pid) throws Error;

		private extern static void _inject_library_file (Windows.ProcessHandle handle, string path, string entrypoint, string data,
			out void * inject_instance, out void * waitable_thread_handle) throws Error;
		private extern static void _free_inject_instance (void * inject_instance, out bool is_resident);
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
		public extern Source create (void * handle, bool owns_handle);
	}
}
