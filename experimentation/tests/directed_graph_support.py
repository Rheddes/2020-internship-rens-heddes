import pytest

import networkx as nx
import numpy as np
import matplotlib.pyplot as plt


def test_adjacency_matrix_for_simple_graph():
    """
    A --> B
    ^     |
    |     v
    D <-- C
    """
    graph = nx.DiGraph()
    graph.add_nodes_from(['A', 'B', 'C', 'D'])
    graph.add_edges_from([('A', 'B'), ('B', 'C'), ('C', 'D'), ('D', 'A')])

    expected_adjacency_matrix = np.array([
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [0, 0, 0, 1],
        [1, 0, 0, 0],
    ])

    print(nx.directed_laplacian_matrix(graph))

    assert np.array_equal(nx.to_numpy_array(graph), expected_adjacency_matrix)


def test_adjacency_matrix_for_fully_connected_graph():
    graph = nx.DiGraph()
    graph.add_nodes_from(['A', 'B', 'C', 'D'])
    graph.add_edges_from([('A', 'B'), ('B', 'C'), ('C', 'D'), ('D', 'A')])
    graph.add_edges_from([('B', 'A'), ('C', 'B'), ('D', 'C'), ('A', 'D')])
    graph.add_edges_from([('A', 'C'), ('C', 'A'), ('B', 'D'), ('D', 'B')])

    expected_adjacency_matrix = np.array([
        [0, 1, 1, 1],
        [1, 0, 1, 1],
        [1, 1, 0, 1],
        [1, 1, 1, 0],
    ])

    assert np.array_equal(nx.to_numpy_array(graph), expected_adjacency_matrix)


def test_graph():
    """
    Example graph from: http://ceadserv1.nku.edu/longa//classes/mat385_resources/docs/matrix.html
    """
    graph = nx.DiGraph()
    graph.add_nodes_from(['A', 'B', 'C', 'D', 'E'])
    graph.add_edges_from([('A', 'B'), ('A', 'D'), ('A', 'E'), ('B', 'D'), ('C', 'E'), ('E', 'B')])

    expected_adjacency_matrix = np.array([
        [0, 1, 0, 1, 1],
        [0, 0, 0, 1, 0],
        [0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0],
    ])

    assert np.array_equal(nx.to_numpy_array(graph), expected_adjacency_matrix)
