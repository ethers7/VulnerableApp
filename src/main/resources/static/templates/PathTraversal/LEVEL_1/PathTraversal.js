// Safe object property access to prevent prototype pollution
function safeGet(obj, key) {
  if (!obj || typeof obj !== "object") {
    return undefined;
  }
  if (key === "__proto__" || key === "constructor" || key === "prototype") {
    return undefined;
  }
  const hasOwn = Object.hasOwn || function(o, k) {
    return Object.prototype.hasOwnProperty.call(o, k);
  };
  return hasOwn(obj, key) ? obj[key] : undefined;
}

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
      const firstRow = content[0];
      if (firstRow && typeof firstRow === "object") {
        for (let key in firstRow) {
          if (!firstRow.hasOwnProperty(key)) {
            continue;
          }
          tableInformation =
            tableInformation + '<th id="InfoColumn">' + key + "</th>";
        }
      }
    }
    for (let index in content) {
      if (!content.hasOwnProperty(index)) {
        continue;
      }
      tableInformation = tableInformation + '<tr id="Info">';
      const row = safeGet(content, index);
      if (row && typeof row === "object") {
        for (let key in row) {
          if (!row.hasOwnProperty(key)) {
            continue;
          }
          const cellValue = safeGet(row, key);
          tableInformation =
            tableInformation +
            '<td id="InfoColumn">' +
            cellValue +
            "</td>";
        }
      }
      tableInformation = tableInformation + "</tr>";
    }
    tableInformation = tableInformation + "</table>";
    document.getElementById("Information").innerHTML = tableInformation;
  } else {
    document.getElementById("Information").innerHTML = "Unable to Load Users";
  }
}
