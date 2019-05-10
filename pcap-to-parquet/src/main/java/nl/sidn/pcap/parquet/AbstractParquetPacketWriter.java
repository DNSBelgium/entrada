/*
 * ENTRADA, a big data platform for network data analytics
 *
 * Copyright (C) 2016 SIDN [https://www.sidn.nl]
 * 
 * This file is part of ENTRADA.
 * 
 * ENTRADA is free software: you can redistribute it and/or modify it under the terms of the GNU
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * ENTRADA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with ENTRADA. If not, see
 * [<http://www.gnu.org/licenses/].
 *
 */
package nl.sidn.pcap.parquet;

import nl.sidn.pcap.support.PacketCombination;
import nl.sidn.pcap.util.GeoLookupUtil;
import org.apache.avro.generic.GenericRecord;
import org.apache.avro.generic.GenericRecordBuilder;
import org.apache.commons.io.FileUtils;
import org.kitesdk.data.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class AbstractParquetPacketWriter {

  protected static final Logger LOGGER = LoggerFactory.getLogger(AbstractParquetPacketWriter.class);

  // show status every 100k rows;
  protected static final int STATUS_COUNT = 100000;

  protected int packetCounter;
  // writer vars
  protected DatasetDescriptor descriptor;
  protected DatasetWriter<GenericRecord> writer;
  protected String schema;
  // meta info
  protected GeoLookupUtil geoLookup;
  protected Map<String, String> geo_ip_cache = new HashMap<>();
  protected Map<String, String> asn_cache = new HashMap<>();
  // metrics
  protected Set<String> countries = new HashSet<>();

  public AbstractParquetPacketWriter(String schema, GeoLookupUtil geoLookup) {
    this.geoLookup = geoLookup;
    this.schema = schema;
    LOGGER.info("constructed with schema: {}", schema);
  }


  /**
   * use caching for maxmind otherwise cpu usage will be high and app will stall
   *
   * @param lookup ip address to look up
   * @return determined country
   */
  protected String getCountry(String lookup) {
    String country = geo_ip_cache.get(lookup);
    if (country == null) {
      country = geoLookup.lookupCountry(lookup);
      if (country != null) {
        geo_ip_cache.put(lookup, country);
        countries.add(country);
      }
    }

    return country;
  }

  /**
   * use caching for maxmind otherwise cpu usage will be high and app will stall
   *
   * @param lookup IP address
   * @return found ASN
   */
  protected String getAsn(String lookup) {
    String asn = asn_cache.get(lookup);
    if (asn == null) {
      asn = geoLookup.lookupASN(lookup);
      if (asn != null) {
        asn_cache.put(lookup, asn);
      }
    }

    return asn;
  }

  /**
   * create a parquet record which combines values from the query and the response
   *
   * @param packet a combo of query and response packets
   */
  public abstract void write(PacketCombination packet);

  /**
   * Create the partion strategy for the data, e.g. year, month,day
   *
   * @return the partion strategy to use
   */
  protected abstract PartitionStrategy createPartitionStrategy();

  public void open(String path) {


    LOGGER.info("Create new Parquet writer with path {}", path);

    /* before opening, make sure there is no (old) .metadata folder in the output dir */
    String metadataLocation = path + System.getProperty("file.separator") + ".metadata";
    try {
      FileUtils.deleteDirectory(new File(metadataLocation));
    } catch (IOException e1) {
      throw new RuntimeException("Could not remove old .metadata directory -> " + metadataLocation);
    }

    /*
     * create a partition for year, month and day. The parquetwriter will create a directory
     * structure with the distinct partition values.
     */
    PartitionStrategy partitionStrategy = createPartitionStrategy();
    // create a descriptor with the parquet output format and the correct partition strategy
    try {
      descriptor = new DatasetDescriptor.Builder().schemaUri("resource:" + schema)
          .format(Formats.PARQUET).partitionStrategy(partitionStrategy).build();
    } catch (Exception e) {
      throw new RuntimeException("Error while creating data descriptor", e);
    }

    String uri = "dataset:file:" + path;
    LOGGER.info("Creating a dataset with URI = {}", uri);
    Dataset<GenericRecord> dataset = Datasets.create(uri, descriptor, GenericRecord.class);
    writer = dataset.newWriter();

    LOGGER.info("Created new Parquet writer");
  }

  /**
   * Create a new builder for every row.
   *
   * @return a new builder
   */
  protected GenericRecordBuilder newBuilder() {
    return new GenericRecordBuilder(descriptor.getSchema());
  }

  public void close() {
    showStatus();

    if (writer != null && writer.isOpen()) {
      writer.close();
    }
  }

  protected void showStatus() {
    LOGGER.info("---------- " + this.getClass().getSuperclass().getSimpleName()
        + " Parquet writer status --------------------");
    LOGGER.info(packetCounter + " packets written to parquet file.");
    LOGGER.info("-----------------------------------------------------");
    LOGGER.info("countries: {}", countries.size());
    LOGGER.info("asn_cache: {}", asn_cache.size());
    LOGGER.info("geo_ip_cache: {}", geo_ip_cache.size());
    LOGGER.info("geo_ip_cache: {}", geo_ip_cache.size());
    LOGGER.info("asn_cache: {}", asn_cache.size());
  }

  /**
   * replace all non printable ascii chars with the hex value of the char.
   *
   * @param str the input
   * @return the input string with all non printable ascii chars replaced with the hex value of the char.
   */
  public String filter(String str) {
    StringBuilder filtered = new StringBuilder(str.length());
    for (int i = 0; i < str.length(); i++) {
      char current = str.charAt(i);
      if (current >= 0x20 && current <= 0x7e) {
        filtered.append(current);
      } else {
        filtered.append("0x").append(Integer.toHexString(current));
      }
    }

    return filtered.toString();
  }

  public abstract void writeMetrics();

  protected void updateMetricMap(Map<Integer, Integer> map, Integer key) {
    Integer currentVal = map.get(key);
    //noinspection Java8MapApi
    if (currentVal != null) {
      map.put(key, currentVal + 1);
    } else {
      map.put(key, 1);
    }
  }

}

