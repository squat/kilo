import React from 'react';
import classnames from 'classnames';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './styles.module.css';

const features = [
  {
    title: <>Runs on Kubernetes</>,
    imageUrl: 'https://kubernetes.io/images/nav_logo.svg',
    description: (
      <>
        Kilo can be installed on any Kubernetes cluster, allowing nodes located in different clouds or in different countries to form a single cluster.
      </>
    ),
    clip: true,
    width: "215px",
  },
  {
    title: <>Built on WireGuard</>,
    imageUrl: 'https://www.wireguard.com/img/wireguard.svg',
    description: (
      <>
        Kilo uses <a href="https://www.wireguard.com/">WireGuard</a>, a performant and secure VPN, to create a mesh between the different nodes in a cluster.
      </>
    ),
    clip: true,
    width: "187px",
  },
  {
    title: <>Advanced Features</>,
    imageUrl: 'img/kilo.svg',
    description: (
      <>
        Kilo brings advanced networking functionality to Kubernetes clusters, like <a href="docs/vpn">accessing Pods via VPN</a> and creating <a href="docs/multi-cluster-services">multi-cluster services</a>.
      </>
    ),
  },
];

function Feature({imageUrl, title, description, clip, width}) {
  const imgUrl = useBaseUrl(imageUrl);
  const imgStyle = {};
  if (width) {
      imgStyle.width = width;
  }
  return (
    <div className={classnames('col col--4', styles.feature)}>
      {imgUrl && (
        <div className="text--center">
          <img className={classnames(styles.featureImage, clip && styles.featureImageClip)} src={imgUrl} alt={title} style={imgStyle} />
        </div>
      )}
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}

function Home() {
  const context = useDocusaurusContext();
  const {siteConfig = {}} = context;
  return (
    <Layout
      title={`Build multi-cloud Kubernetes clusters`}
      description="Kilo is a multi-cloud network overlay built on WireGuard and designed for Kubernetes (k8s + wg = kg)">
      <header className={classnames('hero hero--primary', styles.heroBanner)}>
        <div className="container">
          <h1 className="hero__title">{siteConfig.title}</h1>
          <p className="hero__subtitle">{siteConfig.tagline}</p>
          <div className={styles.buttons}>
            <Link
              className={classnames(
                'button button--outline button--secondary button--lg',
                styles.getStarted,
              )}
              to={useBaseUrl('docs/introduction')}>
              Get Started
            </Link>
          </div>
        </div>
      </header>
      <main>
        {features && features.length && (
          <section className={styles.features}>
            <div className="container">
              <div className="row">
                {features.map((props, idx) => (
                  <Feature key={idx} {...props} />
                ))}
              </div>
            </div>
          </section>
        )}
      </main>
    </Layout>
  );
}

export default Home;
