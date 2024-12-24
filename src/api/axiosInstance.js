import {saveJwtToken} from "../store";
import axios from "axios";
import store from "../store";

const apiClient=axios.create({
    baseURL:"http://localhost:8080",
    headers:{
        "Content-Type" : "application/json",

    },
// timeout:3000,
});



apiClient.interceptors.request.use((config) => {
    // 1. 요청 데이터가 URLSearchParams 타입인지 확인
    if (config.data instanceof URLSearchParams) {
        config.headers["Content-Type"] = "application/x-www-form-urlencoded";
    }
    const jwtToken=store.getState().userInfo.jwtToken;
    config.headers["authorization"]=jwtToken;

    return config; // 수정된 config 반환
}, (error) => {
    // 요청을 가로채는 중에 에러 발생 시 처리
    return Promise.reject(error);
});

apiClient.interceptors.response.use(
    (response) => response, // 정상 응답은 그대로 반환
    async (error) => {
        const originalRequest = error.config;
        // 401 Unauthorized 처리
        if (error.response && error.response.status === 401 && !originalRequest._retry) {
            originalRequest._retry = true; // 무한 루프 방지 플래그 설정
            try {
                // 리프레시 토큰을 사용하여 새 액세스 토큰 발급 요청
                const refreshResponse = await axios.post("http://localhost:8080/reissue",
                    null,
                    { withCredentials: true }
                );

                const newAccessToken = refreshResponse.headers["authorization"];
                // Redux 스토어에 새 액세스 토큰 저장
                store.dispatch(saveJwtToken(newAccessToken));
                // 원래 요청에 새 액세스 토큰 추가
                console.log("만료된 요청 재시도");

                return apiClient(originalRequest);
            } catch (refreshError) {
                console.error('리프레시 토큰으로 재발급 실패:', refreshError);
                // 재발급 실패 시 에러 전달 (로그아웃 처리 등 추가 가능)
                return Promise.reject(refreshError);
            }
        }

        return Promise.reject(error); // 다른 에러는 그대로 반환
    }
);




export default apiClient;