namespace Frida {
	public class ForkMonitor : Object, Gum.InvocationListener {
		public weak ForkHandler handler {
			get;
			construct;
		}

		private static void * fork_impl;
		private static void * vfork_impl;

		public ForkMonitor (ForkHandler handler) {
			Object (handler: handler);
		}

		static construct {
			unowned string libc = Gum.Process.query_libc_name ();
			fork_impl = Gum.Module.find_export_by_name (libc, "fork");
			vfork_impl = Gum.Module.find_export_by_name (libc, "vfork");
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			interceptor.attach (fork_impl, this);
			interceptor.replace (vfork_impl, fork_impl);
		}

		public override void dispose () {
			var interceptor = Gum.Interceptor.obtain ();

			interceptor.revert (vfork_impl);
			interceptor.detach (this);

			base.dispose ();
		}

		private void on_enter (Gum.InvocationContext context) {
			handler.prepare_to_fork ();
		}

		private void on_leave (Gum.InvocationContext context) {
			int result = (int) context.get_return_value ();
			if (result != 0) {
				handler.recover_from_fork_in_parent ();
			} else {
				handler.recover_from_fork_in_child (null);
			}
		}
	}
}
