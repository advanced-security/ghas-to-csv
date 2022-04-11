# GitHub Advanced Security to CSV

Simple GitHub Action to scrape the GitHub Advanced Security API and shove it into a CSV.  

## Why?

Because I really want to see this data for a repository as a time-series to understand it, and [flat data](https://next.github.com/projects/flat-data/) doesn't support paginated APIs (yet?) ... so ... it's really an experiment.

Also ... some people just like CSV files and want to do things in spreadsheets and I'm not here to judge that.  Shine on, you Excel gurus! :sparkling:

## How

This got a little more complicated than I'd like, but the tl;dr of what I'm trying to figure out is below:

```mermaid
graph TD;
    "this action"-->"csv files";
    "csv files"-->"actions/upload-artifact";
    "actions/upload-artifact"-->"flat data";
    "flat data"-->"data goodness";
```

Obviously if you're only wanting the CSV file, run this thing, then download the artifacts.  You're ready to rock and roll. :)

## But it doesn't do THIS THING

The API docs are [here](https://docs.github.com/en/enterprise-cloud@latest) and pull requests are welcome! :heart:
