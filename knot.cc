#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <cstdlib>
using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::pair;
using std::string;
using std::istringstream;
using std::vector;

struct Edge;

struct Vertex
{
    Vertex(string str) : name(str) {;}
    string name;
    vector<Edge*> e;
};

struct Edge
{ 
    Edge(Vertex *a, Vertex *b) : first(a), second(b) {;}
    Vertex *first;
    Vertex *second;
};

struct Graph
{
    vector<Vertex *> v;
    vector<Edge *> e;
    Vertex *findVertex(const string str)
    {
        vector<Vector *>::const_itr vitr;
        for (vitr=v.begin(); vitr!=v.end(); ++vitr)
          if ((*vitr)->name == str)
            return *vitr;
    }

    return new Vertex(str);
};

static void to_knot(const Graph &g)
{
    // (0) For each vertex of G
    vector<Vertex*>::const_iterator vitr;
    for (vitr=g.v.begin(); vitr!=g.v.end(); ++vitr)
    {
        Vertex *v = *vitr;
        vector<Edge*>::const_iterator eitr;
        for (eitr=v->e.begin(); eitr!=v->e.end(); ++eitr)
        {
            // (1) Create set of incident egdes (and their corresponding vertex)
            // to the vertex.
            // vitr..e are the incident edges
        } 
    }

    /* 2) For each set in 1) If any of the verticies making up the edges in the
     * set also share an edge with the verticies making up edges in another set
     * (also created in 1)) then we have an intersection.
     */
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << endl;
        exit(EXIT_FAILURE);
    }

    ifstream in(argv[1]);
    if (!in.is_open())
    {
        cerr << "Could not open input file" << endl;
        exit(EXIT_FAILURE);
    }

    Graph graph;
    while (in.good())
    {
        string a, b;
        in >> a >> b;
        if (!a.length())
          break;
        a.pop_back();     

        Vertex *caller = g.findVertex(a);
        Vertex *callee = g.findVertex(b);
        Edge   *edge   = new Edge(caller, callee);

        caller->e.push_back(edge);
        callee->e.push_back(edge);

        graph.v.push_back(caller);
        graph.v.push_back(callee);
    }

    to_knot(graph);
    in.close();

    return 0;
}
