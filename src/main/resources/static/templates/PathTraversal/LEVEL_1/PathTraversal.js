function addingEventListenerToLoadImageButton() {
  document.getElementById("loadButton").addEventListener("click", function () {
    let url = getUrlForVulnerabilityLevel();
    doGetAjaxCall(
      appendResponseCallback,
      url + "?fileName=" + document.getElementById("fileName").value,
      true
    );
  });
}
addingEventListenerToLoadImageButton();

function appendResponseCallback(data) {
  if (data.isValid) {
    let tableInformation = '<table id="InfoTable">';
    let content = JSON.parse(data.content);
    if (content.length > 0) {
      for (let key in content[0]) {
        tableInformation =
          tableInformation + '<th id="InfoColumn">' + key + "</th>";
      }
    }
    content.forEach(function(row) {
      tableInformation = tableInformation + '<tr id="Info">';
      Object.keys(row).forEach(function(key) {
        tableInformation =
          tableInformation +
          '<td id="InfoColumn">' +
          row[key] +
          "</td>";
      });
      tableInformation = tableInformation + "</tr>";
    });
    tableInformation = tableInformation + "</table>";
    document.getElementById("Information").innerHTML = tableInformation;
  } else {
    document.getElementById("Information").innerHTML = "Unable to Load Users";
  }
}
