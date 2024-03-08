"use client";

import { useState } from 'react';
import dynamic from 'next/dynamic';
import Image from 'next/image';
import styles from '../page.module.css';

const LoginComponent = () => {

    const [showNumbers, setShowNumbers] = useState(false);
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('');

    // pages/index.js or the specific page you're working with

    const LoginComponent = dynamic(() => import('./LoginComponent'), {
        ssr: false, // This will only render the component client-side
    });

    const handleLogin = () => {
        if (username === 'admin' && password === '0728') {
            setMessage('Sucesso');
        } else {
            setMessage('Login falhou. Tente novamente.');
        }
    };


    return (
        <div className={styles.container}>
            <h1>Login</h1>
            <input
                type="text"
                placeholder="E-mail"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
            />
            <input
                type="password"
                placeholder="****"
                onFocus={() => setShowNumbers(true)}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
            />
            {showNumbers && (
                <div>
                    {[['0', '8'], ['1', '9'], ['2', '7'], ['3', '4'], ['5', '6']].map((pair, index) => (
                        <button key={index} onClick={() => setPassword(password + pair[0])}>
                            {pair[0]} ou {pair[1]}
                        </button>
                    ))}
                    <button onClick={() => setPassword(password.slice(0, -1))}>
                        <Image
                            src="/delete.svg"
                            alt="Delete"
                            width={24}
                            height={24}
                        />
                    </button>
                </div>
            )}
            <button onClick={handleLogin}>Log in</button>
            <p>{message}</p>
            <a href="#">Forgot password?</a>
        </div>
    );
};

export default LoginComponent;
