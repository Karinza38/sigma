import os,glob
import yaml
from yaml.loader import SafeLoader
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-f","--folder")
args = parser.parse_args()

folder_path = f'.\\rules\\windows\\{args.folder}'


for filename in glob.glob(os.path.join(folder_path, '*.yml')):
  with open(filename, 'r') as f:
    # text = f.read()
    # print (filename)
    dataset = list(yaml.load_all(f, Loader=SafeLoader))

    for data in dataset:
        print(f"{filename}, {data.get('title')}, {data.get('id')}")
    # print (len(text))