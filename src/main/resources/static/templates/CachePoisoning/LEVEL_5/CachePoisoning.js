import {
  clearCacheAndFetchFreshResponse,
  clearInputs,
  fetchDataCallback,
  getHeadersWithForwardedHost,
  getInputValue,
  getRequestUrl,
  setDemoUser,
} from "../Common/CachePoisoningCommon.js";

function sendAttackerRequest() {
  doGetAjaxCall(
    fetchDataCallback,
    getRequestUrl(),
    true,
    getHeadersWithForwardedHost()
  );
}

document
  .getElementById("poisonCacheBtn")
  .addEventListener("click", function () {
    const demoUser = getInputValue("demoUserInput");
    clearInputs(["demoUserInput"]);
    if (demoUser) {
      setDemoUser(demoUser, sendAttackerRequest);
    } else {
      sendAttackerRequest();
    }
  });

document.getElementById("resetCacheBtn").addEventListener("click", function () {
  setDemoUser(null, clearCacheAndFetchFreshResponse);
});

document
  .getElementById("victimRequestBtn")
  .addEventListener("click", function () {
    setDemoUser(null, function () {
      doGetAjaxCall(fetchDataCallback, getRequestUrl(), true, {});
    });
  });
