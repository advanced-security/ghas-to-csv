# Contributing

Hi there! We're thrilled that you'd like to contribute to this project. Your help is essential for keeping it great.

Contributions to this project are [released](https://help.github.com/articles/github-terms-of-service/#6-contributions-under-repository-license) to the public under the [project's open source license](LICENSE).

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## Submitting a pull request

1. Fork and clone the repository
1. Configure and install the dependencies: `pip3 install -r requirements.txt`
1. Create a new branch: `git checkout -b my-branch-name`
1. Push to your fork and submit a pull request
1. Pat your self on the back and wait for your pull request to be reviewed! :tada:

Here are a few things you can do that will increase the likelihood of your pull request being accepted:

- Follow the [style guide](https://black.readthedocs.io/en/stable/) - it'll automatically run via the [super-linter](https://github.com/github/super-linter).
- Write tests.
- Keep your change as focused as possible. If there are multiple changes you would like to make that are not dependent upon each other, consider submitting them as separate pull requests.
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).

## Local development

After cloning your forked repository, you can set up your development environment by running the following commands:

```bash
# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip3 install -r requirements.txt
```

To execute the python script `main.py` locally you will need to setup the required environment variables. You can do this by making a copy of `.env-sample` into `.env` file in the root of the project and edit the values to match your environment.

```bash
source .env
```

You can now run the script locally:

```bash
python3 main.py
```

## Resources

- [How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
- [Using Pull Requests](https://help.github.com/articles/about-pull-requests/)
- [GitHub Help](https://help.github.com)
