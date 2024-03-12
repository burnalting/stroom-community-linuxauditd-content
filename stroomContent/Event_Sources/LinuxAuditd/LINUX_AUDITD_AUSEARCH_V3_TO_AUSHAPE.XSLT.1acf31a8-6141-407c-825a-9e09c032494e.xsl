<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet xpath-default-namespace="records:2" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="3.0">

  <!--
  20221231:
  Fix bug where we removed '-' from element names inadvertantly. Element names can have embedded or trailing '-'s
  -->
  <xsl:template match="records">
    <log>
      <xsl:apply-templates />
    </log>
  </xsl:template>

  <!-- 
  Ausearch Simple key value pair records are converted to aushape XML output
  -->

  <!-- Main record template -->
  <xsl:template match="record">

    <!--
    A record maps to an aushape event which has attributes of
    
    serial - the auditd event serial
    time - the auditd event time. We note that the time from auditd will be yyyy-MM-dd'T'HH:mm:ss.SSS but fixed at UTC
    host - the node value for the auditd event
    -->
    <event>
      <xsl:attribute name="serial" select="data[1]/data[@name='eventId']/@value" />
      <xsl:attribute name="time" select="data[1]/data[@name='eventTime']/@value" />
      <xsl:attribute name="host" select="data[1]/data[@name='node']/@value" />
      <data>

        <!-- We treat path, avc lines separately -->
        <xsl:for-each select="data[not(@value='PATH' or @value='AVC')]">

          <!-- We do this sort, as aushape outputs the sub-records in reverse order to ausearch -->
          <xsl:sort select="position()" data-type="number" order="descending" />

          <!-- We can get types with a value like UNKNOWN[1333], so just in case we translate the brackets to underscores -->
          <xsl:element name="{replace(lower-case(@value), '\[|\]', '_')}">

            <!-- We don't need type, node, eventTime, eventId or argc key value pairs when converting to aushape format -->
            <xsl:for-each select="data[not(@name='type' or @name='node' or @name='eventTime' or @name='eventId' or @name='argc')]">

              <!-- Some keys have non qname characters, strip them hyphen, space, open brace -->

              <!-- 20221231: A hyphen is a legal qname -->
              <xsl:element name="{translate(@name,' (', '')}">
                <xsl:attribute name="i" select="@value" />
              </xsl:element>
            </xsl:for-each>
          </xsl:element>
        </xsl:for-each>

        <!-- If we have a path, output each path as it's own 'item' element -->
        <xsl:if test="data[@value='PATH']">
          <path>
            <xsl:for-each select="data[@value='PATH']">

              <!-- We do this sort, as aushape outputs the sub-records in reverse order to ausearch -->
              <xsl:sort select="position()" data-type="number" order="descending" />
              <item>

                <!-- We don't need type, node, eventTime or eventId value pairs when converting to aushape format -->
                <xsl:for-each select="data[not(@name='type' or @name='node' or @name='eventTime' or @name='eventId')]">
                  <xsl:element name="{@name}">
                    <xsl:attribute name="i" select="@value" />
                  </xsl:element>
                </xsl:for-each>
              </item>
            </xsl:for-each>
          </path>
        </xsl:if>

        <!-- If we have avc, put each as it's own 'item' element and also ensure AVC's at end -->
        <xsl:if test="data[@value='AVC']">
          <avc>
            <xsl:for-each select="data[@value='AVC']">

              <!-- We do this sort, as aushape outputs the sub-records in reverse order to ausearch -->
              <xsl:sort select="position()" data-type="number" order="descending" />
              <item>

                <!-- We don't need type, node, eventTime or eventId value pairs when converting to aushape format -->
                <xsl:for-each select="data[not(@name='type' or @name='node' or @name='eventTime' or @name='eventId')]">
                  <!--
                  TODO: There are sometimes unusual `@name` values that are causing fatal errors, like the following, which is an invalid element name:
                  <data name="/var/log/remote/2022/07/03/anotherdir/anotherdir" value="2022-07-03_23_3__2022_07_03_20_00.log" />
                  -->
                  <xsl:element name="{@name}">
                    <xsl:attribute name="i" select="@value" />
                  </xsl:element>
                </xsl:for-each>
              </item>
            </xsl:for-each>
          </avc>
        </xsl:if>
      </data>
    </event>
  </xsl:template>
</xsl:stylesheet>
