# 1. Create the namespace
sudo ip netns add ns1

# 2. Create the virtual cable (veth0 <-> veth1)
sudo ip link add veth0 type veth peer name veth1

# 3. Move veth1 end into the namespace
sudo ip link set veth1 netns ns1

# 4. Assign IP to Host side (veth0) - The Driver
sudo ip addr add 10.0.0.10/24 dev veth0
sudo ip link set veth0 up

# 5. Assign IP to Namespace side (veth1) - The Server
sudo ip netns exec ns1 ip addr add 10.0.0.11/24 dev veth1
sudo ip netns exec ns1 ip link set veth1 up

# 6. Turn off offloading (Crucial for AF_XDP with fixed frame sizes)
sudo ethtool -K veth0 gro off lro off gso off tso off
sudo ip netns exec ns1 ethtool -K veth1 gro off lro off gso off tso off

# 7. Verify connectivity
ping -c 2 10.0.0.11