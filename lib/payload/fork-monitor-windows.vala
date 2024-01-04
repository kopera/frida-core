namespace Frida {
	public class ForkMonitor : Object, Gum.InvocationListener {
		public weak ForkHandler handler {
			get;
			construct;
		}

		public ForkMonitor (ForkHandler handler) {
			Object (handler: handler);
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			var msys_fork = Gum.Module.find_export_by_name ("msys-2.0.dll", "fork");
			if (msys_fork != null) {
				interceptor.attach (msys_fork, this);
			}
		}

		public override void dispose () {
			var interceptor = Gum.Interceptor.obtain ();

			interceptor.detach (this);

			base.dispose ();
		}

		private void on_enter (Gum.InvocationContext context) {
			printerr ("fork-monitor: on_msys_fork_enter\n");
			handler.prepare_to_fork ();
		}

		private void on_leave (Gum.InvocationContext context) {
			printerr ("fork-monitor: on_msys_fork_leave\n");
			int result = (int) context.get_return_value ();
			if (result != 0) {
				handler.recover_from_fork_in_parent ();
			} else {
				handler.recover_from_fork_in_child (null);
			}
		}
	}
}