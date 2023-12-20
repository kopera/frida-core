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

		private enum HookId {
			CREATE_PROCESS_INTERNAL_W,
			MSYS_FORK,
			MSYS_SPAWNVE
		}

		private Private create_process_internal_w_caller_is_internal = new Private ();

		public SpawnMonitor (SpawnHandler handler, MainContext main_context) {
			Object (handler: handler, main_context: main_context);
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			var create_process_internal = Gum.Module.find_export_by_name ("kernelbase.dll", "CreateProcessInternalW");
			if (create_process_internal == null)
				create_process_internal = Gum.Module.find_export_by_name ("kernel32.dll", "CreateProcessInternalW");
			assert (create_process_internal != null);
			interceptor.attach (create_process_internal, this, (void *) HookId.CREATE_PROCESS_INTERNAL_W);

			var msys_fork = Gum.Module.find_export_by_name ("msys-2.0.dll", "fork");
			if (msys_fork != null) {
				interceptor.attach (msys_fork, this, (void *) HookId.MSYS_FORK);
			}
			var msys_spawnve = Gum.Module.find_export_by_name ("msys-2.0.dll", "spawnve");
			if (msys_spawnve != null) {
				interceptor.attach (msys_spawnve, this, (void *) HookId.MSYS_SPAWNVE);
			}
		}

		public override void dispose () {
			var interceptor = Gum.Interceptor.obtain ();

			interceptor.detach (this);

			base.dispose ();
		}

		private void on_enter (Gum.InvocationContext context) {
			var hook_id = (HookId) context.get_listener_function_data ();
			switch (hook_id) {
				case CREATE_PROCESS_INTERNAL_W: on_create_process_internal_w_enter (context); break;
				case MSYS_FORK:                 on_msys_fork_enter (context); break;
				case MSYS_SPAWNVE:              on_msys_spawnve_enter (context); break;
				default:                        assert_not_reached ();
			}
		}

		private void on_leave (Gum.InvocationContext context) {
			var hook_id = (HookId) context.get_listener_function_data ();
			switch (hook_id) {
				case CREATE_PROCESS_INTERNAL_W: on_create_process_internal_w_leave (context); break;
				case MSYS_FORK:                 on_msys_fork_leave (context); break;
				case MSYS_SPAWNVE:              on_msys_spawnve_leave (context); break;
				default:                        assert_not_reached ();
			}
		}

		// CreateProcessInternalW
		private void on_create_process_internal_w_enter (Gum.InvocationContext context) {
			var caller_is_internal = (bool) create_process_internal_w_caller_is_internal.get ();
			if (caller_is_internal)
				return;

			CreateProcessInvocation * invocation = context.get_listener_invocation_data (sizeof (CreateProcessInvocation));

			invocation.application_name = (string16?) context.get_nth_argument (1);
			invocation.command_line = (string16?) context.get_nth_argument (2);

			invocation.creation_flags = (uint32) context.get_nth_argument (6);
			context.replace_nth_argument (6, (void *) (invocation.creation_flags | CreateProcessFlags.CREATE_SUSPENDED));

			invocation.environment = context.get_nth_argument (7);

			invocation.process_info = context.get_nth_argument (10);
		}

		private void on_create_process_internal_w_leave (Gum.InvocationContext context) {
			var caller_is_internal = (bool) create_process_internal_w_caller_is_internal.get ();
			if (caller_is_internal)
				return;

			var success = (bool) context.get_return_value ();
			if (!success)
				return;

			CreateProcessInvocation * invocation = context.get_listener_invocation_data (sizeof (CreateProcessInvocation));

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

		// msys fork
		private void on_msys_fork_enter (Gum.InvocationContext context) {
			create_process_internal_w_caller_is_internal.set ((void *) true);
		}

		private void on_msys_fork_leave (Gum.InvocationContext context) {
			create_process_internal_w_caller_is_internal.set ((void *) false);

			int result = (int) context.get_return_value ();
			if (result > 0) {
				var parent_pid = get_process_id ();
				var child_pid = result;
				var info = HostChildInfo (child_pid, parent_pid, ChildOrigin.SPAWN);
				handler.on_spawn_created ();
			}
		}

		// msys spawnve
		private void on_msys_spawnve_enter (Gum.InvocationContext context) {
			create_process_internal_w_caller_is_internal.set ((void *) true);

			SpawnInvocation * invocation = context.get_listener_invocation_data (sizeof (SpawnInvocation));
			invocation.mode = (SpawnMode)(((int) context.get_nth_argument (0)) & 0xfff);
			invocation.pid = Frida.get_process_id ();

			if (invocation.mode == SpawnMode.OVERLAY) {
				unowned string? path = (string?) context.get_nth_argument (1);
				var argv = parse_strv ((string **) context.get_nth_argument (2));
				var envp = parse_strv ((string **) context.get_nth_argument (3));

				var info = HostChildInfo (invocation.pid, invocation.pid, ChildOrigin.EXEC);
				fill_child_info_path_argv_and_envp (ref info, path, argv, envp);

				on_exec_imminent (&info);
			}
		}

		private void on_msys_spawnve_leave (Gum.InvocationContext context) {
			create_process_internal_w_caller_is_internal.set ((void *) false);

			SpawnInvocation * invocation = context.get_listener_invocation_data (sizeof (SpawnInvocation));
			if (invocation.mode == SpawnMode.OVERLAY) {
				on_exec_cancelled (invocation.pid);
			}
		}

		private void on_exec_imminent (HostChildInfo * info) {
			mutex.lock ();

			OperationStatus status = QUEUED;

			var source = new IdleSource ();
			source.set_callback (() => {
				perform_prepare_to_exec.begin (info, &status);
				return false;
			});
			source.attach (main_context);

			while (status != COMPLETED)
				cond.wait (mutex);

			mutex.unlock ();
		}

		private async void perform_prepare_to_exec (HostChildInfo * info, OperationStatus * status) {
			yield handler.prepare_to_exec (info);

			notify_operation_completed (status);
		}

		private void on_exec_cancelled (uint pid) {
			mutex.lock ();

			OperationStatus status = QUEUED;

			var source = new IdleSource ();
			source.set_callback (() => {
				perform_cancel_exec.begin (pid, &status);
				return false;
			});
			source.attach (main_context);

			while (status != COMPLETED)
				cond.wait (mutex);

			mutex.unlock ();
		}

		private async void perform_cancel_exec (uint pid, OperationStatus * status) {
			yield handler.cancel_exec (pid);

			notify_operation_completed (status);
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

		private struct CreateProcessInvocation {
			public unowned string16? application_name;
			public unowned string16? command_line;

			public uint32 creation_flags;

			public void * environment;

			public CreateProcessInfo * process_info;
		}

		private struct SpawnInvocation {
			public SpawnMode mode;
			public uint pid;
		}

		public struct CreateProcessInfo {
			public void * process;
			public void * thread;
			public uint32 process_id;
			public uint32 thread_id;
		}

		[Flags]
		private enum CreateProcessFlags {
			CREATE_SUSPENDED		= 0x00000004,
			CREATE_UNICODE_ENVIRONMENT	= 0x00000400,
		}

		private enum SpawnMode {
			WAIT		= 1,
			NOWAIT		= 2,
			OVERLAY		= 3,
			NOWAITO		= 4,
			DETACH		= 5
		}

		public extern static uint32 _resume_thread (void * thread);
		public extern static string[] _get_environment ();
		public extern static string[] _parse_unicode_environment (void * env);
		public extern static string[] _parse_ansi_environment (void * env);


		private static void fill_child_info_path_argv_and_envp (ref HostChildInfo info, string? path, string[]? argv, string[]? envp) {
			if (path != null)
				info.path = path;

			if (argv != null) {
				info.has_argv = true;
				info.argv = argv;
			}

			if (envp != null) {
				info.has_envp = true;
				info.envp = envp;
			}
		}

		private unowned string[]? parse_strv (string ** strv) {
			if (strv == null)
				return null;

			unowned string[] elements = (string[]) strv;
			return elements[0:strv_length (elements)];
		}

		private void notify_operation_completed (OperationStatus * status) {
			mutex.lock ();
			*status = COMPLETED;
			cond.broadcast ();
			mutex.unlock ();
		}
	}
}
