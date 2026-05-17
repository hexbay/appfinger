package customrules

import (
	"context"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

var DefaultProvider = &customTemplateGitHubRepo{
	owner:       "hexbay",
	repo:        "finger-rules",
	gitCloneURL: "http://github.com/hexbay/finger-rules",
	githubToken: "",
}

type customTemplateGitHubRepo struct {
	owner       string
	repo        string
	gitCloneURL string
	githubToken string
}

// All Custom GitHub repos are cloned in the format of 'owner/repo' for uniqueness
func (customTemplate *customTemplateGitHubRepo) getLocalRepoClonePath(downloadPath string) string {
	//return filepath.Join(downloadPath, customTemplate.owner, customTemplate.repo)
	return downloadPath
}

// Download This function download the custom GitHub template repository
func (customTemplate *customTemplateGitHubRepo) Download(ctx context.Context, local string) {
	clonePath := customTemplate.getLocalRepoClonePath(local)
	if !fileutil.FolderExists(clonePath) {
		err := customTemplate.cloneRepo(clonePath, customTemplate.githubToken)
		if err != nil {
			gologger.Error().Msgf("%s", err)
		} else {
			gologger.Info().Msgf("Repo %s/%s cloned successfully at %s", customTemplate.owner, customTemplate.repo, clonePath)
		}
		return
	}
}

func (customTemplate *customTemplateGitHubRepo) Update(ctx context.Context, local string) {
	clonePath := customTemplate.getLocalRepoClonePath(local)
	// If folder does not exits then clone/download the repo
	if !fileutil.FolderExists(clonePath) {
		customTemplate.Download(ctx, local)
		return
	}
	err := customTemplate.pullChanges(clonePath, customTemplate.githubToken)
	if err != nil {
		gologger.Error().Msgf("%s", err)
	} else {
		gologger.Info().Msgf("Repo %s/%s successfully pulled the changes.\n", customTemplate.owner, customTemplate.repo)
	}
}

// download the git repo to a given path
func (customTemplate *customTemplateGitHubRepo) cloneRepo(clonePath, githubToken string) error {
	r, err := git.PlainClone(clonePath, false, &git.CloneOptions{
		URL:  customTemplate.gitCloneURL,
		Auth: getAuth(customTemplate.owner, githubToken),
	})
	if err != nil {
		return errors.Errorf("%s/%s: %s", customTemplate.owner, customTemplate.repo, err.Error())
	}
	// Add the user as well in the config. By default, user is not set
	config, _ := r.Storer.Config()
	config.User.Name = customTemplate.owner
	return r.SetConfig(config)
}

// returns the auth object with username and GitHub token as password
func getAuth(username, password string) *http.BasicAuth {
	if username != "" && password != "" {
		return &http.BasicAuth{Username: username, Password: password}
	}
	return nil
}

// performs the git pull on given repo
func (customTemplate *customTemplateGitHubRepo) pullChanges(repoPath, githubToken string) error {
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}
	w, err := r.Worktree()
	if err != nil {
		return err
	}
	err = w.Pull(&git.PullOptions{RemoteName: "origin", Auth: getAuth(customTemplate.owner, githubToken)})
	if err != nil {
		return errors.Errorf("%s/%s: %s", customTemplate.owner, customTemplate.repo, err.Error())
	}
	return nil
}
