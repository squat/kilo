module.exports = {
  docs: [
    {
      type: 'doc',
      id: 'introduction',
    },
    {
      type: 'category',
      label: 'Guides',
      items: ['topology', 'vpn', 'vpn-server', 'multi-cluster-services', 'network-policies', 'userspace-wireguard'],
    },
    {
      type: 'category',
      label: 'Reference',
      items: ['annotations', 'kg', 'kgctl'],
    },
    //Features: ['mdx'],
  ],
};
