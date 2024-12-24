import React, {useState} from "react";
import axios from "axios";
import {useSelector, useDispatch} from "react-redux";
import {login, logout, saveJwtToken} from "./store";
import apiClient from "./api/axiosInstance";

function Login() {
    const dispatch=useDispatch();
    const csrfToken=useSelector(state=>state.userInfo.csrfToken);
    console.log("토큰:", csrfToken);
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState("");

    const handleLogin = async (e) => {
        e.preventDefault();
        try {
            const response = await apiClient.post("/login",
                new URLSearchParams({ username, password }),{
                    withCredentials:true
                } // x-www-form-urlencoded 방식
            );

            const token=response.headers["authorization"];
            await dispatch(saveJwtToken(token));
            //로그인 후에는 서버에서 csrf토큰을 갱신한다 갱신된 토큰을 다시 받는다.
            console.log("jwt토큰 : ", token);
            console.log("")
            await dispatch(login());

        } catch (error) {
            console.log(error.response.data.error);
            // console.log(error.response.data);
            setMessage("Login failed");
        }
    };

    const handleJoin = async (e) => {
        e.preventDefault();
        try {
            const response = await apiClient.post("/join",
                { username, password },
            );
            setMessage(response.data); // 성공 메시지

        } catch (error) {
            console.log(error);
            setMessage("Login failed");
        }
    };

    return (
        <div>
            <form>
                <input
                    type="text"
                    placeholder="Username"
                    value={username}
                    // ref={usernameRef}
                    onChange={(e) => setUsername(e.target.value)}
                />
                <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    // ref={passwordRef}
                    onChange={(e) => setPassword(e.target.value)}
                />
                <button type="button" name="login" onClick={handleLogin}>Login</button>
                <button type="button" name="join" onClick={handleJoin}>Join</button>
            </form>
            {message && <p>{message}</p>}
        </div>
    );
}

export default Login;
