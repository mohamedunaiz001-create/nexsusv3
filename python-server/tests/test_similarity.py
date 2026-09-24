from app.malware_intel.similarity import find_similar


def test_similarity_returns_explainable_component_scores():
    query = [1.0] * 14
    matches = find_similar(query, [{"id": "sample-1", "name": "sample.bin", "vector": query}], top_n=1)

    assert len(matches) == 1
    match = matches[0]
    assert match.score == 100.0
    assert match.contentSimilarity == 100.0
    assert match.iocSimilarity == 100.0
    assert match.networkSimilarity == 100.0
    assert match.behaviorSimilarity == 100.0
    assert match.structureSimilarity == 100.0
