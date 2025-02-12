#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>

/*
 * ペイロードのうち、\r\nSP の SP のインデクスを返す。
 * 見付からなければ -1 を返す。
 */
static int
findCRLFSP(void const *payload, void const *data_end)
{
	int state = 0;

	for (int i = 0; payload + i < data_end && i < 1024; i++) {
		/* \r\n を探す */
		if (*(char *)(payload + i) == "\r\n "[state])
			state++;
		else
			state = 0;
		if (state == 3)
			return i;
	}

	return -1;
}

/*
 * 文字列の IPv4 アドレスを 16 進数に変換する
 */
uint32_t
convert_ipv4_into_hex(const char *ip_str)
{
	struct in_addr addr;

	if (inet_pton(AF_INET, ip_str, &addr) == 1)
		return ntohl(addr.s_addr);
	else
		fprintf(stderr, "provided FROMADDR is not a valid IPv4 address\n");
		abort();
}

int SEC("prog")
icom(struct xdp_md *ctx)
{
	/*
	 * (long) は本来 (intptr_t) であるべき。<stdint.h> を #include すると
	 * ヘッダファイルの依存関係でトチるっぽい（えっ？）
	 */
	void * const data = (void *)(long)ctx->data;
	void * const data_end = (void *)(long)ctx->data_end;

	/* Ethernet データフレームより短かかったら何もしない */
	struct ethhdr * const eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* IP ヘッダより短かったら何もしない */
	struct iphdr * const ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	/* UDP パケットでなければ何もしない */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* UDP パケットより短かったら何もしない */
	struct udphdr * const udp = (struct udphdr *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;

	
	/* ユーザによって指定された差出人を、環境変数から読み取る */
	const char *from_addr_env = getenv("FROMADDR")
	if !(from_addr_env)
		fprintf(stderr, "FROMADDR is not specified\n");
		abort();

	/*
	 * ユーザから提供された IPv4 アドレスを示す文字列を解釈する
	 * 複数指定するときは、コンマ区切りで指定しなければならない
	 *
	 * e.g.
	 *	単数のとき、`192.0.2.1`
	 *	複数のとき、`192.0.2.1,192.0.2.2`
	 */
	char *from_addr_tokenize_source = strdup(from_addr_env);
	if (!from_addr_tokenize_source)
		fprintf(stderr, "provided FROMADDR is invalid\n");
		abort();

	/* コンマで区切られた IPv4 アドレスを分割する */
	char *from_addr = strtok(from_addr_tokenize_source, ",");
	bool from_addr_is_icom = false;
	while (from_addr)
		/* 関係のある IPv4 アドレスであるかを判定する */
		if (ip->saddr == __constant_htonl(convert_ipv4_into_hex(from_addr)))
			from_addr_is_icom = true;
		/* 複数個 IPv4 アドレスが提供されたとき、次のアドレスへシークする */
		from_addr = strtok(NULL, ",");
	
	/* 関係ない差出人だったら何もしない（ホストオーダ） */
	if !(from_addr_is_icom)
		return XDP_PASS;

	/* 関係ないポート宛だったら何もしない（ホストオーダ） */
#define DESTPORT	5060
	if (udp->dest != __constant_htons(DESTPORT))
		return XDP_PASS;

	/*
	 * とりあえずヘッダ行を連結してみる。
	 * XXX: 連結されてほしいヘッダ行は Authorization: の行だが、それより前
	 * に二行に渡るヘッダがある場合にはそれが連結されてしまいそう。まあ、
	 * しょうがないかもね。
	 */
	void * const payload = (void *)(udp + 1);
	int spindex = findCRLFSP(payload, data_end);
	if (spindex < 0)
		return XDP_PASS;
	*(char *)(payload + spindex - 2) = ',';
	*(char *)(payload + spindex - 1) = ' ';

	/* チェックサムをポイする */
	udp->check = 0;

	return XDP_PASS;
}
