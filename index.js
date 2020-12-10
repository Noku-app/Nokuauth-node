const oauth = require("./src/oauth")
var express = require("express")

var app = express();
app.use("/oauth", oauth);
app.listen(3333, async () => {})

app.get("/", (req, res) => {
    res.send({})
})