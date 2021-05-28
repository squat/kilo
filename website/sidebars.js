module.exports = {
  docs: [
    {
      type: 'doc',
      id: 'introduction',
    },
    {
      type: 'category',
      label: 'Guides',
      items: ['topology', 'vpn', 'vpn-server', 'multi-cluster-services', 'network-policies', 'userspace-wireguard', 'peer-validation'],
    },
    {
      type: 'category',
      label: 'Reference',
      items: ['annotations', 'kg', 'kgctl', 'api'],
    },
    {
      type: 'category',
      label: 'Contributing',
      items: ['building_kilo', 'building_website'],
    },
    //Features: ['mdx'],
  ],
};
