package nl.sidn.pcap.parquet;

import nl.sidn.pcap.support.PacketCombination;

public interface ParquetWriter {

  void open(String path);

  void close();

  /**
   * create 1 parquet record which combines values from the query and the response
   *
   * @param combo the combo to write to parquet
   */
  void write(PacketCombination combo);

}
