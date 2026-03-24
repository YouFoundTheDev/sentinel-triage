from data.load_bq import load_schema


def test_schema_columns_and_modes() -> None:
    schema = load_schema()

    assert [field.name for field in schema] == [
        "url",
        "domain",
        "label",
        "threat_type",
        "first_seen",
        "source",
    ]
    by_name = {field.name: field for field in schema}
    assert by_name["first_seen"].field_type == "DATE"
    assert by_name["domain"].mode == "REQUIRED"
    assert by_name["url"].mode == "NULLABLE"
