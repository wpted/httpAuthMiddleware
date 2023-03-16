package middlewares

import "net/http"

// HandlerFunction wraps func(handlerFunc http.HandlerFunc) http.HandlerFunc
type HandlerFunction func(handlerFunc http.HandlerFunc) http.HandlerFunc

// Middleware object
type Middleware struct {
	Method          string
	HandlerFunction HandlerFunction
}

// MiddlewareChain is a chain that contains all input middlewares
type MiddlewareChain []Middleware

// NewMiddleware creates a new Middleware
func NewMiddleware(method string, handlerFunc HandlerFunction) (*Middleware, error) {
	switch method {
	case "basic":
		return &Middleware{
			Method:          "",
			HandlerFunction: handlerFunc,
		}, nil
	default:
		return nil, nil
	}
}

// CreateChain takes the input middlewares and turn it into a usable chain
func CreateChain(middlewares ...Middleware) (middlewareList MiddlewareChain) {
	return append(middlewareList, middlewares...)
}

// Use registers every middleware in the chain
func (c MiddlewareChain) Use(handlerFunc http.HandlerFunc) http.HandlerFunc {
	for idx := range c {
		// assign new handler applying from the start of the middleware list
		// implementing middlewares in the correct order matters!
		handlerFunc = c[idx].HandlerFunction(handlerFunc)
	}
	return handlerFunc
}
