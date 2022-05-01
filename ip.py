import ipaddress
import struct
from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.identificador = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama

            _, _, comprimento, \
            identificador, _, \
            time_to_live, _, _, \
            origem, destino = struct.unpack('!BBHHHBBHII', datagrama[:20])
            time_to_live -= 1

            if (time_to_live <= 0):
                cabecalho_icmp = struct.pack('!BBHI', 11, 0, 0, 0)
                pacote_icmp = cabecalho_icmp + datagrama[:28]
                checksum_icmp = calc_checksum(pacote_icmp)
                cabecalho_icmp = struct.pack('!BBHI', 11, 0, checksum_icmp, 0)
                pacote_icmp = cabecalho_icmp + datagrama[:28]

                next_hop = self._next_hop(origem)
                cabecalho_ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(pacote_icmp),
                                            identificador, 0,
                                            64, 1, 0)
                cabecalho_ip = cabecalho_ip + str2addr(self.meu_endereco) + struct.pack('!I', origem)
                checksum_ip = calc_checksum(cabecalho_ip)
                cabecalho_ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(pacote_icmp),
                                            identificador, 0,
                                            64, 1, checksum_ip)
                cabecalho_ip = cabecalho_ip + str2addr(self.meu_endereco) + struct.pack('!I', origem)

                datagrama = cabecalho_ip + pacote_icmp
                self.enlace.enviar(datagrama, next_hop)
                return

            cabecalho = struct.pack('!BBHHHBBHII', 0x45, 0, comprimento,
                                    identificador, 0,
                                    time_to_live, 6, 0,
                                    origem, destino)
            checksum = calc_checksum(cabecalho)
            cabecalho = struct.pack('!BBHHHBBHII', 0x45, 0, comprimento,
                                    identificador, 0,
                                    time_to_live, 6, checksum,
                                    origem, destino)
            datagrama = cabecalho + payload
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        destino = ipaddress.ip_network(dest_addr)

        for tupla in self.tabela:
            entrada = ipaddress.ip_network(tupla[0])
            saida = tupla[1]

            if (destino.subnet_of(entrada)):
                return saida

        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.

        self.tabela = []

        for tupla in tabela:
            entrada = tupla[0]
            saida = tupla[1]
            bits = int(tupla[0].split('/')[1])
            self.tabela.append((entrada, saida, bits))
        
        self.tabela.sort(key=lambda tupla: tupla[2], reverse=True)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        self.identificador += 1
        cabecalho = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(segmento),
                                self.identificador, 0,
                                64, 6, 0)
        cabecalho = cabecalho + str2addr(self.meu_endereco) + str2addr(dest_addr)
        checksum = calc_checksum(cabecalho)
        cabecalho = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(segmento),
                                self.identificador, 0,
                                64, 6, checksum)
        cabecalho = cabecalho + str2addr(self.meu_endereco) + str2addr(dest_addr)

        datagrama = cabecalho + segmento

        self.enlace.enviar(datagrama, next_hop)
