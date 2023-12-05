namespace Frida {
	public interface SpawnHandler : Object {
		public abstract async void prepare_to_exec (HostChildInfo * info);
		public abstract async void cancel_exec (uint pid);
		public abstract async void acknowledge_spawn (HostChildInfo * info, SpawnStartState start_state);
	}
}
