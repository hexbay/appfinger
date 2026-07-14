package customrules

import (
	"context"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"os"
	"path/filepath"
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

// Download downloads the custom GitHub template repository.
func (customTemplate *customTemplateGitHubRepo) Download(ctx context.Context, local string) error {
	ctx = normalizeContext(ctx)
	clonePath := customTemplate.getLocalRepoClonePath(local)
	if !fileutil.FolderExists(clonePath) {
		err := customTemplate.cloneRepoWithContext(ctx, clonePath, customTemplate.githubToken)
		if err != nil {
			gologger.Error().Msgf("%s", err)
			return err
		} else {
			gologger.Info().Msgf("Repo %s/%s cloned successfully at %s", customTemplate.owner, customTemplate.repo, clonePath)
		}
	}
	return nil
}

func (customTemplate *customTemplateGitHubRepo) Update(ctx context.Context, local string) error {
	ctx = normalizeContext(ctx)
	clonePath := customTemplate.getLocalRepoClonePath(local)
	// If folder does not exits then clone/download the repo
	if !fileutil.FolderExists(clonePath) {
		return customTemplate.Download(ctx, local)
	}
	err := customTemplate.pullChangesWithContext(ctx, clonePath, customTemplate.githubToken)
	if err != nil {
		gologger.Error().Msgf("%s", err)
		return err
	} else {
		gologger.Info().Msgf("Repo %s/%s successfully pulled the changes.\n", customTemplate.owner, customTemplate.repo)
	}
	return nil
}

// EnsureDefaultDirectory ensures the default finger-rules directory exists.
func EnsureDefaultDirectory(ctx context.Context) (string, error) {
	directory := GetDefaultDirectory()
	return directory, EnsureDirectory(ctx, directory)
}

// EnsureDirectory ensures a finger-rules repository exists at directory.
func EnsureDirectory(ctx context.Context, directory string) error {
	ctx = normalizeContext(ctx)
	if directory == "" {
		return fmt.Errorf("empty rules directory")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if fileutil.FolderExists(directory) {
		return nil
	}
	parent := filepath.Dir(directory)
	if parent != "" {
		if err := os.MkdirAll(parent, os.ModePerm); err != nil {
			return fmt.Errorf("create rules parent directory failed: %w", err)
		}
	}
	return DefaultProvider.Download(ctx, directory)
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// download the git repo to a given path
func (customTemplate *customTemplateGitHubRepo) cloneRepo(clonePath, githubToken string) error {
	return customTemplate.cloneRepoWithContext(context.Background(), clonePath, githubToken)
}

func (customTemplate *customTemplateGitHubRepo) cloneRepoWithContext(ctx context.Context, clonePath, githubToken string) error {
	r, err := git.PlainCloneContext(ctx, clonePath, false, &git.CloneOptions{
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
	return customTemplate.pullChangesWithContext(context.Background(), repoPath, githubToken)
}

func (customTemplate *customTemplateGitHubRepo) pullChangesWithContext(ctx context.Context, repoPath, githubToken string) error {
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}
	w, err := r.Worktree()
	if err != nil {
		return err
	}
	err = w.PullContext(ctx, &git.PullOptions{RemoteName: "origin", Auth: getAuth(customTemplate.owner, githubToken)})
	if err != nil {
		if err == git.NoErrAlreadyUpToDate {
			return nil
		}
		return errors.Errorf("%s/%s: %s", customTemplate.owner, customTemplate.repo, err.Error())
	}
	return nil
}
