# MongoDB connection / collections and populate the DB with data from json.

import json
from pathlib import Path
from utils.helpers import green, red, blue, reset
from db.db_operations import insert_document
from connection.connect_db import MONGO_COLLECTIONS

DATA_FOLDER = Path("./data")


def load_json(file_path: Path) -> list:

    if not file_path.exists():
        print(red + f"File {file_path} does not exists!" + reset)
        return []
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
            print(blue + f"Loaded data from {file_path.name}" + reset)
            return data if isinstance(data, list) else [data]
    except json.JSONDecodeError as e:
        print(red + f"Error decoding JSON from {file_path} : {e}" + reset)
        return []


def seed_collection(collection_key: str, data: list):

    if not data:
        print(blue + f"No data to seed for collection: {collection_key}" + reset)
        return
    for document in data:
        insert_document(collection_key, document)
    print(green + f"Seeded {len(data)} document(s) into {collection_key}" + reset)


def main():

    for collection_key in MONGO_COLLECTIONS.keys():
        json_file = DATA_FOLDER / f"{collection_key}.json"

        print(blue + f"Processing {collection_key} from {json_file.name},..." + reset)
        data = load_json(json_file)
        seed_collection(collection_key, data)

    print(green + "Database seeding completed successfully!" + reset)


if __name__ == "__main__":
    main()
