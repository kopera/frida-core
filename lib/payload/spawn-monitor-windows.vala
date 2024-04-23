namespace Frida {
	public class SpawnMonitor : Object, Gum.InvocationListener {
		public weak SpawnHandler handler {
			get;
			construct;
		}

		public MainContext main_context {
			get;
			construct;
		}

		private Mutex mutex;
		private Cond cond;

		public enum OperationStatus {
			QUEUED,
			COMPLETED
		}

		public SpawnMonitor (SpawnHandler handler, MainContext main_context) {
			Object (handler: handler, main_context: main_context);
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			var create_process_internal = Gum.Module.find_export_by_name ("kernelbase.dll", "CreateProcessInternalW");
			if (create_process_internal == 0)
				create_process_internal = Gum.Module.find_export_by_name ("kernel32.dll", "CreateProcessInternalW");
			assert (create_process_internal != 0);
			interceptor.attach ((void *) create_process_internal, this);
		}

		public override void dispose () {
			var interceptor = Gum.Interceptor.obtain ();

			interceptor.detach (this);

			base.dispose ();
		}

		private void on_enter (Gum.InvocationContext context) {
			Invocation * invocation = context.get_listener_invocation_data (sizeof (Invocation));

			invocation.application_name = (string16?) context.get_nth_argument (1);
			invocation.command_line = (string16?) context.get_nth_argument (2);

			invocation.creation_flags = (uint32) context.get_nth_argument (6);
			context.replace_nth_argument (6, (void *) (invocation.creation_flags | CreateProcessFlags.CREATE_SUSPENDED));

			invocation.environment = context.get_nth_argument (7);

			invocation.process_info = context.get_nth_argument (10);
		}

		private void on_leave (Gum.InvocationContext context) {
			var success = (bool) context.get_return_value ();
			if (!success)
				return;

			Invocation * invocation = context.get_listener_invocation_data (sizeof (Invocation));

			var pid = invocation.process_info.process_id;
			var parent_pid = get_process_id ();
			var info = HostChildInfo (pid, parent_pid, ChildOrigin.SPAWN);

			string path = null;
			string[] argv;
			try {
				if (invocation.application_name != null)
					path = invocation.application_name.to_utf8 ();

				if (invocation.command_line != null) {
					Shell.parse_argv (invocation.command_line.to_utf8 ().replace ("\\", "\\\\"), out argv);
					if (path == null)
						path = argv[0];
				} else {
					argv = { path };
				}
			} catch (ConvertError e) {
				assert_not_reached ();
			} catch (ShellError e) {
				assert_not_reached ();
			}
			info.path = path;
			info.has_argv = true;
			info.argv = argv;

			string[]? envp = null;
			if (invocation.environment != null) {
				if ((invocation.creation_flags & CreateProcessFlags.CREATE_UNICODE_ENVIRONMENT) != 0)
					envp = _parse_unicode_environment (invocation.environment);
				else
					envp = _parse_ansi_environment (invocation.environment);
				info.has_envp = true;
				info.envp = envp;
			}

			on_spawn_created (&info, SpawnStartState.SUSPENDED);

			if ((invocation.creation_flags & CreateProcessFlags.CREATE_SUSPENDED) == 0)
				_resume_thread (invocation.process_info.thread);
		}

		private void on_spawn_created (HostChildInfo * info, SpawnStartState start_state) {
			mutex.lock ();

			OperationStatus status = QUEUED;

			var source = new IdleSource ();
			source.set_callback (() => {
				perform_acknowledge_spawn.begin (info, start_state, &status);
				return false;
			});
			source.attach (main_context);

			while (status != COMPLETED)
				cond.wait (mutex);

			mutex.unlock ();
		}

		private async void perform_acknowledge_spawn (HostChildInfo * info, SpawnStartState start_state, OperationStatus * status) {
			yield handler.acknowledge_spawn (info, start_state);

			notify_operation_completed (status);
		}

		private struct Invocation {
			public unowned string16? application_name;
			public unowned string16? command_line;

			public uint32 creation_flags;

			public void * environment;

			public CreateProcessInfo * process_info;
		}

		public struct CreateProcessInfo {
			public void * process;
			public void * thread;
			public uint32 process_id;
			public uint32 thread_id;
		}

		[Flags]
		private enum CreateProcessFlags {
			CREATE_SUSPENDED            = 0x00000004,
			CREATE_UNICODE_ENVIRONMENT  = 0x00000400,
		}

		public extern static uint32 _resume_thread (void * thread);
		public extern static string[] _get_environment ();
		public extern static string[] _parse_unicode_environment (void * env);
		public extern static string[] _parse_ansi_environment (void * env);

		private void notify_operation_completed (OperationStatus * status) {
			mutex.lock ();
			*status = COMPLETED;
			cond.broadcast ();
			mutex.unlock ();
		}
	}
}
