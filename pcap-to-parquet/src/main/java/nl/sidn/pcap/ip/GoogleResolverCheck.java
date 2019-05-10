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
package nl.sidn.pcap.ip;

import nl.sidn.pcap.util.Settings;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;

import java.net.UnknownHostException;
import java.util.List;

/**
 * check if an IP address is a Google open resolver. This check uses the list from the Google
 * resolver network: dig TXT locations.publicdns.goog.
 * 
 * @author maarten
 * 
 */
public final class GoogleResolverCheck extends AbstractNetworkCheck {

  public static final int TIMEOUT = 15;
  private static String GOOGLE_RESOLVER_IP_FILENAME = "google-resolvers";
  protected static final Logger LOGGER = LoggerFactory.getLogger(GoogleResolverCheck.class);

  @Override
  protected void init() {
    String hostname = Settings.getInstance().getSetting(Settings.RESOLVER_LIST_GOOGLE);
    try {
      Resolver resolver = new SimpleResolver();
      // dns resolvers may take a long time to return a response.
      resolver.setTimeout(TIMEOUT);
      Lookup lookup = new Lookup(StringUtils.endsWith(hostname, ".") ? hostname : hostname + ".", Type.TXT);
      // always make sure the cache is empty
      lookup.setCache(new Cache());
      lookup.setResolver(resolver);
      Record[] records = lookup.run();
      if (records != null && records.length > 0) {
        parse(records[0]);
      }

      if (subnets.size() == 0) {
        LOGGER.error("No Google resolvers found.");
      }
    } catch (Exception e) {
      LOGGER.error("Problem while adding Google resolvers.", e);
    }
  }

  private void parse(Record record) {
    TXTRecord txt = (TXTRecord) record;
    @SuppressWarnings("unchecked")
    List<String> lines = txt.getStrings();
    for (String line : lines) {
      String[] parts = StringUtils.split(line, " ");
      if (parts.length == 2) {
        LOGGER.info("Add Google resolver IP range: " + parts[0]);

        try {
          bit_subnets.add(Subnet.createInstance(parts[0]));
          subnets.add(parts[0]);
        } catch (UnknownHostException e) {
          LOGGER.error("Problem while adding Google resolver IP range: " + parts[0] + e);
        }
      }
    }
  }

  @Override
  protected String getFilename() {
    return GOOGLE_RESOLVER_IP_FILENAME;
  }

}
