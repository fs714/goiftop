package version

var GitVersion string
var GoVersion string
var BuildTime string
var Version = "0.0.1-dev build on " + BuildTime + "\nGit Commit on " + GitVersion + "\n" + GoVersion
