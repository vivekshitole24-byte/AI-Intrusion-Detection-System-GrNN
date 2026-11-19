from celery import shared_task
from scapy.all import sniff,IP
from .utils.dataset_loader import load_attack_dataset
from celery import shared_task

attack_dict = load_attack_dataset()

@shared_taskdef monitor_network():
     """Continuously monitor real-time network traffic and detect attacks."""

     def detect_attack(packet):
          if packet.haslaye[IP]:
          dst_ip = packet[IP].dst
          protocol = packet.proto 

          attack_type = attack_dict.get((src_ip,dst_ip,protocol))
          if attack_type:
                print(f"🚨 Attack detected! {attack_type} | {src_ip} → {dst_ip}")
                # TODO: Send attack data to the Django dashboard via WebSockets

    sniff(prn=detect_attack, store=False)  # Start packet sniffing



@shared_task
def test_celery():
    return "Celery is working!"
