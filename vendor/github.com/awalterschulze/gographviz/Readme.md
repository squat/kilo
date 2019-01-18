Parses the Graphviz DOT language and creates an interface, in golang, with which to easily create new and manipulate existing graphs which can be written back to the DOT format.

This parser has been created using [gocc](http://code.google.com/p/gocc).

### Example (Parse and Edit) ###

```
graphAst, _ := gographviz.ParseString(`digraph G {}`)
graph := gographviz.NewGraph()
if err := gographviz.Analyse(graphAst, graph); err != nil {
    panic(err)
}
graph.AddNode("G", "a", nil)
graph.AddNode("G", "b", nil)
graph.AddEdge("a", "b", true, nil)
output := graph.String()
```

### Documentation ###

The [godoc](https://godoc.org/github.com/awalterschulze/gographviz) includes some more examples.

### Installation ###
go get github.com/awalterschulze/gographviz

### Tests ###

[![Build Status](https://travis-ci.org/awalterschulze/gographviz.svg?branch=master)](https://travis-ci.org/awalterschulze/gographviz)

### Users ###

  - [aptly](https://github.com/smira/aptly) - Debian repository management tool
  - [gorgonia](https://github.com/chewxy/gorgonia) - A Library that helps facilitate machine learning in Go
  - [imagemonkey](https://imagemonkey.io/graph?editor=true) - Let's create our own image dataset
  - [depviz](https://github.com/moul/depviz) - GitHub dependency visualizer (auto-roadmap)

### Mentions ###

[Using Golang and GraphViz to Visualize Complex Grails Applications](http://ilikeorangutans.github.io/2014/05/03/using-golang-and-graphviz-to-visualize-complex-grails-applications/)
