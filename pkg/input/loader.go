package input

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/snyk/policy-engine/pkg/models"
)

type cachedLocation struct {
	LocationStack LocationStack
	Error         error
}

// Loader loads and collects IaC configurations using a given Detector. It provides
// methods to load and transform configurations into the format expected by the engine
// package.
type Loader struct {
	detector       Detector
	configurations map[string]IACConfiguration

	// The corresponding key in configurations for every loaded path.
	//
	// For example, if you have a HCL configuration under "src/vpc", this may
	// contain many paths, such as "src/vpc/.terraform/modules/vpc/main.tf".
	// This map can be used to map those additional paths back to the canonical
	// input path, "src/vpc".
	loadedPaths map[string]string

	locationCache map[string]cachedLocation
}

// NewLoader constructs a Loader using the given Detector.
func NewLoader(detector Detector) Loader {
	return Loader{
		detector:       detector,
		configurations: map[string]IACConfiguration{},
		loadedPaths:    map[string]string{},
		locationCache:  map[string]cachedLocation{},
	}
}

// Load invokes this Loader's detector on an input and stores any resulting
// configuration. This method will return true if a configuration is detected and loaded
// and false otherwise.
func (l *Loader) Load(detectable Detectable, detectOpts DetectOptions) (bool, error) {
	path := detectable.GetPath()
	conf, err := detectable.DetectType(l.detector, detectOpts)
	if err != nil {
		return false, err
	}
	if conf != nil {
		l.configurations[path] = conf
		l.loadedPaths[path] = path
		for _, p := range conf.LoadedFiles() {
			l.loadedPaths[p] = path
		}
		return true, nil
	} else {
		return false, nil
	}
}

// ToStates will convert the configurations in this Loader to State structs which can be
// used by the engine package.
func (l *Loader) ToStates() []models.State {
	keys := []string{}
	for k := range l.configurations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	states := []models.State{}
	for _, k := range keys {
		states = append(states, l.configurations[k].ToState())
	}
	return states
}

// Location takes a file and attribute path and returns the location of the resource
// or attribute.
func (l *Loader) Location(path string, attributePath []interface{}) (LocationStack, error) {
	canonical, ok := l.loadedPaths[path]
	if !ok {
		return nil, fmt.Errorf("%w: unrecognized file path %v", UnableToResolveLocation, path)
	}

	attribute, err := json.Marshal(attributePath)
	if err != nil {
		location, err := l.configurations[canonical].Location(attributePath)
		if err != nil {
			err = fmt.Errorf("%w: %v", UnableToResolveLocation, err)
		}
		return location, err
	}

	key := path + ":" + string(attribute)
	if cached, ok := l.locationCache[key]; ok {
		return cached.LocationStack, cached.Error
	} else {
		location, err := l.configurations[canonical].Location(attributePath)
		if err != nil {
			err = fmt.Errorf("%w: %v", UnableToResolveLocation, err)
		}
		l.locationCache[key] = cachedLocation{location, err}
		return location, err
	}
}

// Count returns the number of configurations contained in this Loader.
func (l *Loader) Count() int {
	return len(l.configurations)
}
