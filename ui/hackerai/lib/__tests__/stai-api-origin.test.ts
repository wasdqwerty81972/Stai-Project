import { getBackendOrigin } from "../stai-api";

test("prefers the backend origin selected at server runtime", () => {
  document.head.innerHTML =
    '<meta name="stai-backend-origin" content="http://127.0.0.1:6766">';

  expect(getBackendOrigin()).toBe("http://127.0.0.1:6766");
});
