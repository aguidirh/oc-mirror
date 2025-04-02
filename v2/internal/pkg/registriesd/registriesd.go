package registriesd

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/containers/storage/pkg/fileutils"
	"github.com/otiai10/copy"
	"gopkg.in/yaml.v2"
)

const (
	systemRegistriesDirPath string = "/etc/containers/registries.d"
	containersSubPath       string = "containers"
	registriesDSubPath      string = "registries.d"
)

var userRegistriesDir = filepath.FromSlash(".config/containers/registries.d")

func PrepareRegistrydCustomDir(workingDir string, registryHosts map[string]struct{}) error {
	var defaultRegistrydConfigPath, customRegistrydConfigPath string
	var err error

	if defaultRegistrydConfigPath, err = GetDefaultRegistrydConfigPath(); err != nil {
		return fmt.Errorf("error getting the default registryd config path : %w", err)
	}

	customRegistrydConfigPath = GetCustomRegistrydConfigPath(workingDir)

	if err := copyDefaultConfigsToWorkingDir(defaultRegistrydConfigPath, customRegistrydConfigPath); err != nil {
		return fmt.Errorf("error copying default registryd configs to custom registryd config path : %w", err)
	}

	if err := addRegistriesd(customRegistrydConfigPath, registryHosts); err != nil {
		return fmt.Errorf("error adding registriesd to custom registryd config dir")
	}

	return nil
}

func GetDefaultRegistrydConfigPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("unable to determine the current user : %w", err)
	}

	return registriesDirPathWithHomeDir(usr.HomeDir), nil
}

func registriesDirPathWithHomeDir(homeDir string) string {
	// we normally  should look to see if sys.RegistriesDirPath is defined
	// but since oc-mirror doesn´t provide a flag to do that, skipping
	// TODO: have a discussion about introducing such a flag, as in skopeo
	// https://github.com/containers/skopeo/blob/603d37c588b9b8b2a8d82db6dc0136a852a6256d/cmd/skopeo/main.go#L84
	userRegistriesDirPath := filepath.Join(homeDir, userRegistriesDir)
	if err := fileutils.Exists(userRegistriesDirPath); err == nil {
		return userRegistriesDirPath
	}
	// TODO remove me - explanation why: sys.RootForImplicitAbsolutePaths is never set so it is always empty, which makes the code below not necessary.
	// if sys != nil && sys.RootForImplicitAbsolutePaths != "" {
	// 	return filepath.Join(sys.RootForImplicitAbsolutePaths, systemRegistriesDirPath)
	// }

	return systemRegistriesDirPath
}

func GetCustomRegistrydConfigPath(workingDir string) string {
	return filepath.Join(workingDir, containersSubPath, registriesDSubPath)
}

func copyDefaultConfigsToWorkingDir(defaultRegistrydConfigPath, customRegistrydConfigPath string) error {
	// TODO should we define copyOptions such as:
	// AddPermission
	// OnDirExists
	// PreserveOwner
	if err := os.MkdirAll(filepath.Dir(customRegistrydConfigPath), 0755); err != nil {
		return fmt.Errorf("error creating folder %s %w", filepath.Dir(customRegistrydConfigPath), err)
	}

	if err := copy.Copy(defaultRegistrydConfigPath, customRegistrydConfigPath); err != nil {
		return fmt.Errorf("error copying from dir %s to %s %w", defaultRegistrydConfigPath, filepath.Dir(customRegistrydConfigPath), err)
	}

	return nil
}

func addRegistriesd(customizableRegistriesDir string, registries map[string]struct{}) error {
	for reg := range registries {
		if err := addRegistryd(customizableRegistriesDir, reg); err != nil {
			return err
		}
	}
	return nil
}

func addRegistryd(customizableRegistriesDir, registryHost string) error {
	// TODO: if file exists, and use-sigstore-attachements isn't configured, what do you do?
	// override? append? exist in error?
	registryFileName := fileName(registryHost)
	// check the cache file exists
	registryFileAbsPath := filepath.Join(customizableRegistriesDir, registryFileName)

	if _, err := os.Stat(registryFileAbsPath); errors.Is(err, os.ErrNotExist) {
		return createRegistryConfigFile(registryFileAbsPath, registryHost)
	} else if err != nil {
		return fmt.Errorf("error trying to find the registry config file %w", err)
	}
	// if it exists, do you rewrite it? do you leave it?
	return nil
}

func fileName(registryURL string) string {
	return registryURL + ".yaml"
}

func createRegistryConfigFile(registryFileAbsPath, registryHost string) error {
	err := os.MkdirAll(filepath.Dir(registryFileAbsPath), 0755)
	if err != nil {
		return fmt.Errorf("error creating cache")
	}
	registryConfigFile, err := os.Create(registryFileAbsPath)
	if err != nil {
		return fmt.Errorf("error creating registry config file %w", err)
	}
	defer registryConfigFile.Close()
	// add the cache file yaml
	registryConfigStruct := registryConfiguration{
		Docker: map[string]registryNamespace{
			registryHost: {
				UseSigstoreAttachments: true,
			},
		},
	}

	ccBytes, err := yaml.Marshal(registryConfigStruct)
	if err != nil {
		return fmt.Errorf("error marshaling registry config struct %w", err)
	}
	_, err = registryConfigFile.Write(ccBytes)
	if err != nil {
		return fmt.Errorf("error wring the registry config file %w", err)
	}

	return nil
}
