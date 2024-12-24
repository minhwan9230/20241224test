import logo from './logo.svg';
import './App.css';
import Login from "./Login";
import {useRef, useEffect,useState} from "react";
import TestConponent from "./TestConponent";
import {useSelector} from "react-redux";
import {useDispatch} from "react-redux";
import {saveCsrfToken} from "./store";
import axios from "axios";

function App() {

 const loginFlag=useSelector(state=>state.userInfo.loginFlag);
  return (
    <>
      {!loginFlag && <Login></Login>}
      {loginFlag && <TestConponent></TestConponent>}
    </>
  );
}


export default App;
