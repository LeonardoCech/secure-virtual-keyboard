// pages/index.js or the specific page you're working with
import dynamic from 'next/dynamic';
import styles from './page.module.css';

const LoginComponent = dynamic(() => import('./components/LoginComponent'), {
  ssr: false, // This will only render the component client-side
});


export default function Home() {
  return (
    <div className={styles.container}>
      <LoginComponent />
    </div>
  );
}
