import json


def build_context(results, max_chars=12000):
    """Keep whole chunks and assign citation IDs ourselves; no truncating evidence."""
    if type(max_chars) is not int or max_chars < 1:
        raise ValueError("Context budget must be a positive integer")
    sources, seen = [], set()
    for result in results:
        key = (result["source"], result["index"], result["start"], result["end"])
        if key in seen:
            continue
        seen.add(key)
        source = {"source_id": f"S{len(sources) + 1}", "source": result["source"],
                  "index": result["index"], "start": result["start"], "end": result["end"],
                  "text": result["text"], "score": result["score"],
                  "metadata": result.get("metadata", {}),
                  "source_sha256": result.get("source_sha256", "")}
        if len(json.dumps(sources + [source], ensure_ascii=False)) <= max_chars:
            sources.append(source)
    return sources


def build_prompt(question, sources):
    # JSON serialization makes delimiters inside documents ordinary field values.
    return json.dumps({"context": sources, "question": question}, ensure_ascii=False)
