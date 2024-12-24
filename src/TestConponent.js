import axios from "axios";
import {useState} from "react";
import {Link} from "react-router-dom";
import {useEffect} from "react";
import {useSelector, useDispatch} from "react-redux";
import {saveJwtToken} from "./store";
import apiClient from "./api/axiosInstance";

export default function TestConponent(){
    const [message, setMessage] = useState("");
    const dispathch=useDispatch();

    const jwtToken=useSelector(state=>state.userInfo.jwtToken);
    console.log("jwt 토큰:", jwtToken);

    const handleAdmin=async (e)=>{
        try{
            const response=await apiClient.get("/admin");
                setMessage(response.data);
        }catch(error){
            console.log(error.message);
        }

    };

    const hadleLogout=async (e)=>{
        dispathch(saveJwtToken(null));
        setMessage("로그아웃되었습니다.");
    }

    return(
        <>
        <button onClick={hadleLogout}>LOGOUT</button>
        <button onClick={handleAdmin}>ADMIN</button>
        <h1>{message}</h1>

        </>
    );
}