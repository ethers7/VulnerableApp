import {
  clearCacheAndFetchFreshResponse,
  clearInputs,
  fetchDataCallback,
  getInputValue,
  getRequestUrl,
  setDemoUser,
} from "../Common/CachePoisoningCommon.js";

function sendLevelRequest() {
  doGetAjaxCall(
    fetchDataCallback,
    getRequestUrl({ bannerInputId: null }),
    true,
    {}
  );
}

document
  .getElementById("poisonCacheBtn")
  .addEventListener("click", function () {
    const demoUser = getInputValue("demoUserInput");
    clearInputs(["demoUserInput"]);
    if (demoUser) {
      setDemoUser(demoUser, sendLevelRequest);
    } else {
      sendLevelRequest();
    }
  });

document.getElementById("resetCacheBtn").addEventListener("click", function () {
  setDemoUser(null, clearCacheAndFetchFreshResponse);
});

document
  .getElementById("victimRequestBtn")
  .addEventListener("click", function () {
    setDemoUser(null, sendLevelRequest);
  });
