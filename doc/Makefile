#
#  $Id: Makefile,v 2.0 2006/04/13 10:37:18 ethuerm Exp $
#

#
#  Low Level CAN Framework
#
#  Makefile for LaTeX documentation
#
#  Copyright (c) 2005 Volkswagen Group Electronic Research
#  38436 Wolfsburg, GERMANY
#
#  contact email: llcf@volkswagen.de
#
#  Idea, Design, Implementation:
#  Oliver Hartkopp <oliver.hartkopp@volkswagen.de>
#  Dr. Urs Thuermann <urs.thuermann@volkswagen.de>
#  Matthias Brukner <m.brukner@trajet.de>
#
#  Neither Volkswagen Group nor the authors admit liability
#  nor provide any warranty for any of this software.
#  This material is provided "AS-IS".
#
#  Until the distribution is granted by the Volkswagen rights
#  department this sourcecode is under non disclosure and must
#  only be used within projects with the Volkswagen Group.
#

FIG = bcm_mux_filter.fig frame_types.fig llcf_module.fig llcf_overview.fig
EPS = $(patsubst %.fig,%.eps, $(FIG))

all: $(EPS)
	latex llcf-api

clean:
	rm -f *.log *.dvi *.aux *.toc *.fig.bak *~ $(EPS)

%.eps: %.fig
	fig2dev -Leps $^ > $@
