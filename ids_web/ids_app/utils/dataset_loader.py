import pandas as pd
import os

def load_attack_dataset():
    """Load the CICIDS2017 dataset and store attack patterns."""
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    dataset_path = os.path.join(BASE_DIR, "ids_app", "static", "cleaned_dataset_2.csv")
    dataset = pd.read_csv(dataset_path)  
    attack_data = dataset[['Source IP', 'Destination IP', 'Protocol', 'Label']]
    attack_dict = attack_data.set_index(['Source IP', 'Destination IP', 'Protocol']).to_dict()['Label']
    return attack_dict
