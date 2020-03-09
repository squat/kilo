module.exports = {
  title: 'Kilo',
  tagline: 'a multi-cloud network overlay built on WireGuard and designed for Kubernetes',
  url: 'https://kilo.squat.ai',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  organizationName: 'squat',
  projectName: 'kilo',
  themeConfig: {
    navbar: {
      title: 'Kilo',
      logo: {
        alt: 'Kilo',
        src: 'img/kilo.svg',
      },
      links: [
        {
          to: 'docs/introduction',
          activeBasePath: 'docs',
          label: 'Docs',
          position: 'left',
        },
        {
          href: 'https://github.com/squat/kilo',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Introduction',
              to: 'docs/introduction',
            },
            {
              label: 'Topology',
              to: 'docs/topology',
            },
            {
              label: 'VPN',
              to: 'docs/vpn',
            },
          ],
        },
        {
          title: 'Social',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/squat/kilo',
            },
          ],
        },
      ],
    },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl:
            'https://github.com/squat/kilo/edit/master/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
};
