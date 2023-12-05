namespace Frida {
	public interface ForkHandler : Object {
		public abstract void prepare_to_fork ();
		public abstract void recover_from_fork_in_parent ();
		public abstract void recover_from_fork_in_child (string? identifier);

		public abstract void prepare_to_specialize (string identifier);
		public abstract void recover_from_specialization (string identifier);
	}
}
