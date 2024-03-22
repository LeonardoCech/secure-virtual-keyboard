"use client";

import { useState, useEffect } from 'react';
import Image from 'next/image';
import "./LoginComponent.css";
import { Button, Container, Form } from 'react-bootstrap';

import CryptoJS from "crypto-js";


const LoginComponent = () => {

    const [username, setUsername] = useState('');
    const [isValidUsername, setIsValidUsername] = useState(false);
    const [password, setPassword] = useState([]);
    const [fakePassword, setFakePassword] = useState('');
    const [numbers, setNumbers] = useState([]);
    const [showNumbers, setShowNumbers] = useState(false);

    const [secretKey, setSecretKey] = useState('');

    useEffect(() => {
        setNumbers(shuffleNumbers());

        fetch('/secretKey.txt')
            .then((response) => response.text())
            .then((text) => {
                setSecretKey(text.trim());
            });

    }, []);

    useEffect(() => setIsValidUsername(validateEmail(username)), [username]);

    useEffect(() => {
        document.getElementById('goToPassword').disabled = isValidUsername ? false : true;
    }, [isValidUsername]);

    useEffect(() => {
        console.log(password);
    }, [password]);


    const shuffleNumbers = () => {
        // Step 2: Gerar um vetor de números de 0 a 9
        let numbers = Array.from({ length: 10 }, (_, i) => i);

        // Step 2: Embaralhar o vetor
        for (let i = numbers.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [numbers[i], numbers[j]] = [numbers[j], numbers[i]];
        }

        // Step 3: Dividir o vetor embaralhado em 5 vetores menores
        let array = [];
        for (let i = 0; i < numbers.length; i += 2) {
            array.push(numbers.slice(i, i + 2));
        }

        return array;
    }

    const encryptPassword = (password) => {
        const encrypted = CryptoJS.AES.encrypt(password, secretKey).toString();
        return encrypted;
    };

    const validateEmail = (email) => {
        return String(email)
            .toLowerCase()
            .match(
                /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
            );
    };

    const handleEmailChange = (e) => {
        setUsername(e.target.value);
    }

    const handleAskPassword = (_) => {
        if (isValidUsername) {
            document.getElementById('goToPassword').style.display = 'none';
            document.getElementById('goToLogin').style.display = 'block';
            setShowNumbers(true);
        }
    }

    const handleButtonClick = (value) => {
        let auxPassword = password;
        auxPassword.push(value)

        setPassword(auxPassword);
        setFakePassword(fakePassword + '*');
        setNumbers(shuffleNumbers());
    };

    const handleDeleteClick = () => {
        let auxPassword = password;
        auxPassword.pop();

        setPassword(auxPassword)
        setFakePassword(fakePassword.slice(0, -1));
        setNumbers(shuffleNumbers());
    };


    const handleSubmit = async (event) => {
        event.preventDefault();

        // let cryptographedPassword = encryptPassword(JSON.stringify(password));

        var formdata = new FormData();
        formdata.append('username', username);
        formdata.append('password', JSON.stringify(password));

        try {
            const response = await fetch('http://localhost:7000/api/v1/user/sign/in', {
                method: 'POST',
                headers: {
                    'Mime-Type': 'multipart/form-data',
                    //cors headers
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With'
                },
                body: formdata
            });

            if (!response.ok) {
                
                if (response.status === 400)
                    alert('Usuário ou senha inválidos');
                
                return;
            }

            const data = await response.json();

            alert('Usuário e senha corretos');
        }

        catch (error) {
            console.error('API Error:', error);
        }
    };

    return (
        <>
            <div className="login-container">
                <div className="login-background">
                    <img src="/logo.svg"></img>
                </div>
                <div className="login-form">
                    <Container>
                        <h1 className="titleLogin">Login</h1>
                        <Form onSubmit={handleSubmit}>
                            <Form.Group controlId="formBasicUsername">
                                <Form.Control
                                    type="text"
                                    placeholder="E-mail"
                                    value={username}
                                    onChange={handleEmailChange}
                                    className="custom-input"
                                />
                            </Form.Group>

                            {showNumbers && (
                                <Form.Group controlId="formBasicPassword">
                                    <Form.Control
                                        type="password"
                                        placeholder="Senha"
                                        value={fakePassword}
                                        className="custom-input"
                                    />
                                </Form.Group>
                            )}

                            {showNumbers && (
                                <div className="buttonsPassword">
                                    <div className="button-row">
                                        {
                                            numbers.map((pair, index) => (
                                                <Button
                                                    key={index}
                                                    variant="outline-primary"
                                                    className="mr-2 mb-2 rounded-pill buttonLogin"
                                                    onClick={() => handleButtonClick(pair)}
                                                >
                                                    {pair[0]} ou {pair[1]}
                                                </Button>
                                            ))
                                        }
                                        <Button
                                            variant="outline-danger"
                                            className="mb-2 rounded-pill buttonLogin"
                                            onClick={handleDeleteClick}
                                        >
                                            <Image
                                                id='delete-icon'
                                                src="/delete.svg"
                                                alt="Delete"
                                                width={24}
                                                height={24}
                                            />
                                        </Button>
                                    </div>
                                </div>
                            )}

                            <Button variant="primary" id="goToPassword" className="buttonEnter" onClick={handleAskPassword}>
                                Prosseguir
                            </Button>

                            <Button variant="primary" type="submit" id="goToLogin" hidden className="buttonEnter">
                                Entrar
                            </Button>
                        </Form>
                    </Container>
                </div>
            </div>
        </>
    );
};

export default LoginComponent;