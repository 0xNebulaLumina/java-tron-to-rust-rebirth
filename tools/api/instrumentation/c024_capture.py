#!/usr/bin/env python3
"""Normalize guarded C024 JUnit XML into row-specific result records."""
import pathlib, xml.etree.ElementTree as ET

def capture(tree: pathlib.Path, wanted: dict[tuple[str,str],str]):
    observed={}
    for report in tree.glob("framework/build/test-results/test/TEST-*.xml"):
        for case in ET.parse(report).getroot().findall("testcase"):
            key=(case.get("classname", ""),case.get("name", "").split("[")[0])
            if key not in wanted: continue
            failed=case.find("failure") is not None or case.find("error") is not None
            skipped=case.find("skipped") is not None
            observed[key]={"id":wanted[key],"request":f"{key[0]}#{key[1]}","status":"failed" if failed else ("skipped" if skipped else "passed"),"source":"authenticated-java-tron"}
    return observed
