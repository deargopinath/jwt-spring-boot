var subject = "unknown"
var token = "unknown"

$(document).ready(function () {
    hideLogin()
    $("#create-jwt-form").submit(function (event) {
        event.preventDefault()
        requestToken()
    })
})

function requestToken() {
    var input = {}
    input["subject"] = $("#clientURL").val()
    input["user"] = $("#user").val()
    input["account"] = $("#account").val()
    $("#create-jwt-button").prop("disabled", true)

    $.ajax({
        type: "POST",
        contentType: "application/json",
        url: "/api/jwe",
        data: JSON.stringify(input),
        dataType: 'json',
        cache: false,
        timeout: 600000,
        success: function (output) {
            console.log(JSON.stringify(output))
            subject = output["subject"]
            token = output["token"]
            showLogin()
            console.log("SUCCESS : ", output);
            $("#token").html(token)
            $("#create-jwt-button").prop("disabled", false);
        },
        error: function (e) {
            var json = "<h4>Error received from server</h4><pre>"
                + e.responseText + "</pre>"
            $('#error-section').html(json)
            console.log("ERROR : ", e)
            $("#create-jwt-button").prop("disabled", false);
        }
    })
}

function hideLogin() {
    $("#login-section").hide()
}

function showLogin() {
    $("#login-section").show()
}


function login() {
    $.ajax({
        url: subject,
        type: 'get',
        contentType: 'text/html',
        headers: {
            "Authorization": "Bearer " + token
        },
        success: () => {window.open(subject)}
    })
}