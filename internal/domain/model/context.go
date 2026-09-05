package model

// CurrentClientContext packages the destructured 3-table relational application
// parameters to transport authenticated credentials cleanly down request context lifecycles.
type CurrentClientContext struct {
	Application *Application
	Profile     *ApplicationProfile
	Group       *ApplicationGroup
}
